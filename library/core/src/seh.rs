//! Docs

use crate::intrinsics;
use crate::mem::{ManuallyDrop, MaybeUninit};

/// The exception information provided by the operating system.
#[repr(transparent)]
#[derive(Debug)]
pub struct ExceptionInformation(*mut u8);

impl ExceptionInformation {
    /// Get the raw pointer to the exception information.
    pub fn as_raw(self) -> *mut u8 {
        self.0
    }
}

/// Indicates how structured exception handling should proceed for a given exception.
#[derive(Debug)]
pub enum FilterResult {
    /// Execution continues at the instruction that caused the exception.
    ContinueExecution,
    /// The function unwinds until it finds another structured exception handler (i.e. the exception is not handled at all).
    ContinueSearch,
    /// The exception handler is called.
    ExecuteHandler,
}

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_EXECUTE_HANDLER: i32 = 1;

/// SEH.
pub unsafe fn catch_seh<TR, ER, FTry, FFilter, FExcept>(
    try_fn: FTry,
    filter_fn: FFilter,
    except_fn: FExcept,
) -> Result<TR, ER>
where
    FTry: FnOnce() -> TR,
    FFilter: Fn(i32, ExceptionInformation) -> FilterResult,
    FExcept: FnOnce() -> ER,
{
    struct Data<FTry, FFilter, FExcept, TR, ER> {
        try_fn: ManuallyDrop<FTry>,
        filter_fn: FFilter,
        except_fn: ManuallyDrop<FExcept>,
        result: MaybeUninit<Result<TR, ER>>,
    }

    // If try_fn returns successfully, we write the result into `result`.
    // If it throws an SEH exception, the exception filter is called:
    //  - If it returns `FilterResult::ContinueExection`, execution is resumed at the instruction that caused the exception.
    //    This may cause another exception, which will call the exception filter again (thus `FnMut`).
    //  - If it returns `FilterResult::ContinueSearch`, the function unwinds. Note that `Drop` code, including closure drop,
    //    will **not** be executed, as if `mem::forget` was called for them.
    //  - If it returns `FilterResult::ExecuteHandler`, the exception handler is called. Its result is written into `result`.

    let mut data = Data {
        try_fn: ManuallyDrop::new(try_fn),
        filter_fn,
        except_fn: ManuallyDrop::new(except_fn),
        result: MaybeUninit::uninit(),
    };

    let data_ptr = (&raw mut data).cast();

    // SAFETY:
    unsafe {
        if intrinsics::catch_seh(
            do_call::<FTry, FFilter, FExcept, TR, ER>,
            data_ptr,
            do_filter::<FTry, FFilter, FExcept, TR, ER>,
            do_except::<FTry, FFilter, FExcept, TR, ER>,
        ) == 0
        {
            ManuallyDrop::drop(&mut data.except_fn);
        }

        return data.result.assume_init();
    }

    #[inline]
    fn do_call<FTry, FFilter, FExcept, TR, ER>(data: *mut u8)
    where
        FTry: FnOnce() -> TR,
        FFilter: Fn(i32, ExceptionInformation) -> FilterResult,
        FExcept: FnOnce() -> ER,
    {
        // SAFETY: this is the responsibility of the caller, see above.
        unsafe {
            let data = data.cast::<Data<FTry, FFilter, FExcept, TR, ER>>();
            let data = &mut *data;
            let f = ManuallyDrop::take(&mut data.try_fn);

            // Do not drop filter_fn or except_fn here, as we're still in the try block - if dropping panics, they'd be executed!
            data.result.write(Ok(f()));
        }
    }

    #[inline]
    fn do_filter<FTry, FFilter, FExcept, TR, ER>(
        data: *mut u8,
        code: i32,
        exception_information: *mut u8,
    ) -> i32
    where
        FTry: FnOnce() -> TR,
        FFilter: Fn(i32, ExceptionInformation) -> FilterResult,
        FExcept: FnOnce() -> ER,
    {
        // SAFETY: this is the responsibility of the caller, see above.
        unsafe {
            let data = data.cast::<Data<FTry, FFilter, FExcept, TR, ER>>();
            let data = &mut *data;

            match (data.filter_fn)(code, ExceptionInformation(exception_information)) {
                FilterResult::ContinueExecution => EXCEPTION_CONTINUE_EXECUTION,
                FilterResult::ContinueSearch => {
                    // except_fn will not be executed, so we need to drop it.
                    //ManuallyDrop::drop(data.except_fn);

                    // filter_fn will also not be executed anymore, drop it.
                    //ManuallyDrop::drop(data.filter_fn);

                    // TODO: do we want those drops? try_fn can't get dropped

                    EXCEPTION_CONTINUE_SEARCH
                }
                FilterResult::ExecuteHandler => EXCEPTION_EXECUTE_HANDLER,
            }
        }
    }

    #[inline]
    fn do_except<FTry, FFilter, FExcept, TR, ER>(data: *mut u8)
    where
        FTry: FnOnce() -> TR,
        FFilter: Fn(i32, ExceptionInformation) -> FilterResult,
        FExcept: FnOnce() -> ER,
    {
        // SAFETY: this is the responsibility of the caller, see above.
        unsafe {
            let data = data.cast::<Data<FTry, FFilter, FExcept, TR, ER>>();
            let data = &mut *data;
            let f = ManuallyDrop::take(&mut data.except_fn);
            data.result.write(Err(f()));
        }
    }
}
