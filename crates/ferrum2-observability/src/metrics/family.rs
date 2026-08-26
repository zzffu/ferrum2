use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use prometheus_client::encoding::{EncodeLabelSet, EncodeMetric, MetricEncoder, NoLabelSet};
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::metrics::{MetricType, TypedMetric};

#[derive(Debug, Default)]
pub(super) struct CachedCounter {
    value: AtomicU64,
    touched: AtomicBool,
}

impl CachedCounter {
    pub(super) fn inc(&self) {
        self.touched.store(true, Ordering::Relaxed);
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn inc_by(&self, value: u64) {
        self.touched.store(true, Ordering::Relaxed);
        self.value.fetch_add(value, Ordering::Relaxed);
    }
}

impl TypedMetric for CachedCounter {
    const TYPE: MetricType = MetricType::Counter;
}

impl EncodeMetric for CachedCounter {
    fn encode(&self, mut encoder: MetricEncoder) -> fmt::Result {
        encoder.encode_counter::<NoLabelSet, _, u64>(&self.value.load(Ordering::Relaxed), None)
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }

    fn is_empty(&self) -> bool {
        !self.touched.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Default)]
pub(super) struct CachedGauge {
    value: AtomicI64,
    touched: AtomicBool,
}

impl CachedGauge {
    pub(super) fn inc(&self) {
        self.touched.store(true, Ordering::Relaxed);
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dec(&self) {
        self.touched.store(true, Ordering::Relaxed);
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn set(&self, value: i64) {
        self.touched.store(true, Ordering::Relaxed);
        self.value.store(value, Ordering::Relaxed);
    }
}

impl TypedMetric for CachedGauge {
    const TYPE: MetricType = MetricType::Gauge;
}

impl EncodeMetric for CachedGauge {
    fn encode(&self, mut encoder: MetricEncoder) -> fmt::Result {
        encoder.encode_gauge(&self.value.load(Ordering::Relaxed))
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }

    fn is_empty(&self) -> bool {
        !self.touched.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub(super) struct CachedHistogram {
    histogram: Histogram,
    touched: AtomicBool,
}

impl CachedHistogram {
    pub(super) fn new(buckets: impl IntoIterator<Item = f64>) -> Self {
        Self {
            histogram: Histogram::new(buckets),
            touched: AtomicBool::new(false),
        }
    }

    pub(super) fn observe(&self, value: f64) {
        self.histogram.observe(value);
        self.touched.store(true, Ordering::Relaxed);
    }
}

impl TypedMetric for CachedHistogram {
    const TYPE: MetricType = MetricType::Histogram;
}

impl EncodeMetric for CachedHistogram {
    fn encode(&self, encoder: MetricEncoder) -> fmt::Result {
        self.histogram.encode(encoder)
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }

    fn is_empty(&self) -> bool {
        !self.touched.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct ClosedFamily<S, M, const N: usize> {
    entries: [(S, M); N],
}

#[derive(Debug)]
pub(super) struct SharedClosedFamily<S, M, const N: usize> {
    inner: Arc<ClosedFamily<S, M, N>>,
}

impl<S, M, const N: usize> Clone for SharedClosedFamily<S, M, N> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S, M: Default, const N: usize> SharedClosedFamily<S, M, N> {
    pub(super) fn new(labels: [S; N]) -> Self {
        Self {
            inner: Arc::new(ClosedFamily {
                entries: labels.map(|labels| (labels, M::default())),
            }),
        }
    }
}

impl<S, M, const N: usize> SharedClosedFamily<S, M, N> {
    pub(super) fn new_with(labels: [S; N], make_metric: impl Fn() -> M) -> Self {
        let mut labels = labels.into_iter();
        Self {
            inner: Arc::new(ClosedFamily {
                entries: std::array::from_fn(|_| {
                    (
                        labels.next().expect("label count matches family size"),
                        make_metric(),
                    )
                }),
            }),
        }
    }

    pub(super) fn metric(&self, index: usize) -> &M {
        &self.inner.entries[index].1
    }
}

impl<S, M, const N: usize> EncodeMetric for SharedClosedFamily<S, M, N>
where
    S: EncodeLabelSet,
    M: EncodeMetric + TypedMetric,
{
    fn encode(&self, mut encoder: MetricEncoder) -> fmt::Result {
        for (labels, metric) in &self.inner.entries {
            if !metric.is_empty() {
                metric.encode(encoder.encode_family(labels)?)?;
            }
        }
        Ok(())
    }

    fn metric_type(&self) -> MetricType {
        M::TYPE
    }

    fn is_empty(&self) -> bool {
        self.inner
            .entries
            .iter()
            .all(|(_, metric)| metric.is_empty())
    }
}

pub(super) fn single_labels<A: Copy, S, const N: usize>(
    values: &[A],
    make: impl Fn(A) -> S,
) -> [S; N] {
    assert_eq!(values.len(), N);
    std::array::from_fn(|index| make(values[index]))
}

pub(super) fn pair_labels<A: Copy, B: Copy, S, const N: usize>(
    first: &[A],
    second: &[B],
    make: impl Fn(A, B) -> S,
) -> [S; N] {
    assert_eq!(first.len() * second.len(), N);
    std::array::from_fn(|index| {
        let second_index = index % second.len();
        let first_index = index / second.len();
        make(first[first_index], second[second_index])
    })
}

pub(super) fn triple_labels<A: Copy, B: Copy, C: Copy, S, const N: usize>(
    first: &[A],
    second: &[B],
    third: &[C],
    make: impl Fn(A, B, C) -> S,
) -> [S; N] {
    assert_eq!(first.len() * second.len() * third.len(), N);
    std::array::from_fn(|index| {
        let third_index = index % third.len();
        let remaining = index / third.len();
        let second_index = remaining % second.len();
        let first_index = remaining / second.len();
        make(first[first_index], second[second_index], third[third_index])
    })
}

pub(super) fn quadruple_labels<A: Copy, B: Copy, C: Copy, D: Copy, S, const N: usize>(
    first: &[A],
    second: &[B],
    third: &[C],
    fourth: &[D],
    make: impl Fn(A, B, C, D) -> S,
) -> [S; N] {
    assert_eq!(first.len() * second.len() * third.len() * fourth.len(), N);
    std::array::from_fn(|index| {
        let fourth_index = index % fourth.len();
        let remaining = index / fourth.len();
        let third_index = remaining % third.len();
        let remaining = remaining / third.len();
        let second_index = remaining % second.len();
        let first_index = remaining / second.len();
        make(
            first[first_index],
            second[second_index],
            third[third_index],
            fourth[fourth_index],
        )
    })
}

pub(super) const fn pair_index(first: usize, second: usize, second_count: usize) -> usize {
    first * second_count + second
}

pub(super) const fn triple_index(
    first: usize,
    second: usize,
    third: usize,
    second_count: usize,
    third_count: usize,
) -> usize {
    pair_index(first, second, second_count) * third_count + third
}

pub(super) const fn quadruple_index(
    first: usize,
    second: usize,
    third: usize,
    fourth: usize,
    second_count: usize,
    third_count: usize,
    fourth_count: usize,
) -> usize {
    triple_index(first, second, third, second_count, third_count) * fourth_count + fourth
}

pub(super) fn u64_gauge(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub(super) fn usize_gauge(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub(super) fn usize_counter(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
