#![deny(missing_docs)]
#![doc(html_root_url = "http://arcnmx.github.io/result-rs/")]

//! Helpers for dealing with nested `Result` and `Option` types. Convert a
//! `Option<Result<T, E>>` to `Result<Option<T>, E>` and vice versa.
//!
//! `use result::prelude::*` is recommended in order to import the extension
//! traits into scope.

/// Module that contains all extension traits useful for working with nested
/// `Option` and `Result` types.
pub mod prelude {
    pub use super::{ResultOptionExt, ResultIteratorExt};
}

/// Extension trait for nested `Option` and `Result` types.
///
/// Alias of `ResultOptionExt` but could become a distinct separate trait in the
/// future.
pub use ::ResultOptionExt as OptionResultExt;

/// Extension trait for nested `Option` and `Result` types.
pub trait ResultOptionExt {
    /// The inverted output type of the operation.
    type Out;

    /// Inverts a nested `Option<Result<T, E>>` or `Result<Option<T>, E>`
    fn invert(self) -> Self::Out;
}

impl<T, E> OptionResultExt for Option<Result<T, E>> {
    type Out = Result<Option<T>, E>;

    fn invert(self) -> Self::Out {
        match self {
            Some(Err(e)) => Err(e),
            Some(Ok(v)) => Ok(Some(v)),
            None => Ok(None)
        }
    }
}

impl<T, E> ResultOptionExt for Result<Option<T>, E> {
    type Out = Option<Result<T, E>>;

    fn invert(self) -> Self::Out {
        match self {
            Ok(None) => None,
            Ok(Some(v)) => Some(Ok(v)),
            Err(e) => Some(Err(e)),
        }
    }
}

/// Extension trait for iterators that produce `Result` types
pub trait ResultIteratorExt {
    /// `Ok(Val)`
    type Val;
    /// `Err(Err)`
    type Err;

    /// `Iterator::next` inverted returns a `Result`.
    fn next_invert(&mut self) -> Result<Option<Self::Val>, Self::Err>;
}

impl<T, E, I: Iterator<Item=Result<T, E>>> ResultIteratorExt for I {
    type Val = T;
    type Err = E;

    fn next_invert(&mut self) -> Result<Option<Self::Val>, Self::Err> {
        self.next().invert()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_result() {
        use std::iter;
        let mut iter = iter::once(Err::<(), _>(0));

        let err = iter.next();
        assert!(err.invert().is_err());
        assert_eq!(err.invert().invert(), err);

        let none = iter.next();
        assert_eq!(none.invert(), Ok(None));
        assert_eq!(none.invert().invert(), none);
    }
}
