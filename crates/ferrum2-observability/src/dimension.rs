/// Keeps a closed metric dimension's values, wire labels and dense indices in
/// one declaration. Indices are generated from declaration order, never from
/// a separately maintained enum discriminant or family vocabulary.
macro_rules! closed_dimension {
    ($(#[$attribute:meta])* pub enum $name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        $crate::dimension::closed_dimension!(@collect
            [$(#[$attribute])*] $name [] [] ; $($variant => $label,)+);
    };
    (@collect [$($attributes:tt)*] $name:ident [$($done:tt)*] [$($count:tt)*] ;
        $variant:ident => $label:literal, $($rest:tt)*) => {
        $crate::dimension::closed_dimension!(@collect [$($attributes)*] $name
            [$($done)* $variant => ($label, <[()]>::len(&[$($count)*])),]
            [$($count)* (),] ; $($rest)*);
    };
    (@collect [$($attributes:tt)*] $name:ident
        [$($variant:ident => ($label:literal, $index:expr),)+] [$($count:tt)*] ;) => {
        $($attributes)*
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub enum $name { $($variant,)+ }

        impl $name {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant,)+];
            pub(crate) const fn index(self) -> usize {
                match self { $(Self::$variant => $index,)+ }
            }
            pub(crate) const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $label,)+ }
            }
        }
    };
}

pub(crate) use closed_dimension;
