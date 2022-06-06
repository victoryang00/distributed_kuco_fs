use core::mem;
use core::result::Result;
use core::intrinsics::copy_nonoverlapping;

pub enum Error { SizeError }

pub unsafe trait DataBlock : Sized {
    fn extract_from(&mut self, slice: &[u8]) -> Result<usize, Error> {
        let sz = mem::size_of::<Self>();
        if sz > slice.len() {
            Err(Error::SizeError)
        } else {
            unsafe {
                let dst_ptr : *mut u8 = self as *mut Self as *mut u8;
                let src_ptr : *const u8 = slice.as_ptr();
                copy_nonoverlapping(src_ptr, dst_ptr, sz);
            }
            Ok(sz)
        }
    }

    fn dump_into(&self, slice: &mut [u8]) -> Result<usize, Error> {
        let sz = mem::size_of::<Self>();
        if sz > slice.len() {
            Err(Error::SizeError)
        } else {
            unsafe {
                let dst_ptr : *mut u8 = slice.as_mut_ptr();
                let src_ptr : *const u8 = self as *const Self as *const u8;
                copy_nonoverlapping(src_ptr, dst_ptr, sz);
            }
            Ok(sz)
        }
    }
}

macro_rules! unsafe_impl {
    ($t:ty) => {
        unsafe impl DataBlock for $t {}
    }
}

// Primitives
unsafe_impl!(u8);
unsafe_impl!(u16);
unsafe_impl!(u32);
unsafe_impl!(u64);
unsafe_impl!(u128);

unsafe_impl!(i8);
unsafe_impl!(i16);
unsafe_impl!(i32);
unsafe_impl!(i64);
unsafe_impl!(i128);

unsafe_impl!(bool);
unsafe_impl!(char);
unsafe_impl!(isize);
unsafe_impl!(usize);

unsafe_impl!(f32);
unsafe_impl!(f64);


// tuples
unsafe impl<A, B> DataBlock for (A, B)
where
    A : DataBlock,
    B : DataBlock,
{}

unsafe impl<A, B, C> DataBlock for (A, B, C)
where
    A : DataBlock,
    B : DataBlock,
    C : DataBlock,
{}

unsafe impl<A, B, C, D> DataBlock for (A, B, C, D)
where
    A : DataBlock,
    B : DataBlock,
    C : DataBlock,
    D : DataBlock,
{}

unsafe impl<A, B, C, D, E> DataBlock for (A, B, C, D, E)
where
    A : DataBlock,
    B : DataBlock,
    C : DataBlock,
    D : DataBlock,
    E : DataBlock,
{}


// Arraies
unsafe_impl_array!(1024);
