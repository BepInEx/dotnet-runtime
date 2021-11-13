// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Threading;
using System.IO;
using Internal.Runtime.Augments;

namespace Microsoft.Win32.SafeHandles
{
    internal class SafeThreadPoolIOHandle : SafeHandle
    {
        static SafeThreadPoolIOHandle()
        {
        }

        public SafeThreadPoolIOHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            Interop.mincore.CloseThreadpoolIo(handle);
            return true;
        }
    }
}


internal static partial class Interop
{
    internal static unsafe partial class mincore
    {
        [DllImport("api-ms-win-core-com-l1-1-0.dll", CharSet = CharSet.Unicode)]
        internal static extern int CLSIDFromProgID(string lpszProgID, out Guid clsid);

        [DllImport(Libraries.ProcessEnvironment, EntryPoint = "GetCommandLineW")]
        internal static extern unsafe char* GetCommandLine();

        [DllImport("api-ms-win-core-sysinfo-l1-1-0.dll")]
        internal static extern unsafe void GetSystemTimeAsFileTime(long* lpSystemTimeAsFileTime);

        [DllImport("api-ms-win-core-libraryloader-l1-2-0.dll")]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, byte* lpProcName);

        [DllImport("api-ms-win-core-libraryloader-l1-2-0.dll", EntryPoint = "LoadLibraryExW", CharSet = CharSet.Unicode)]
        internal static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, int dwFlags);

        [DllImport("api-ms-win-core-libraryloader-l1-2-0.dll")]
        internal static extern bool FreeLibrary(IntPtr hModule);

        [DllImport(Libraries.ProcessEnvironment, CharSet = CharSet.Unicode, EntryPoint = "GetEnvironmentVariableW")]
        internal static extern unsafe int GetEnvironmentVariable(string lpName, [Out] char[] lpValue, int size);

        [DllImport("api-ms-win-core-processthreads-l1-1-1.dll")]
        internal static extern uint GetCurrentProcessorNumber();

        [DllImport(Libraries.ProcessThreads)]
        internal static extern uint GetCurrentThreadId();

        [DllImport("api-ms-win-core-errorhandling-l1-1-0.dll")]
        internal static extern int GetLastError();

        [DllImport("api-ms-win-core-sysinfo-l1-2-1", EntryPoint = "GetSystemDirectoryW", CharSet = CharSet.Unicode)]
#pragma warning disable CA1838 // Avoid 'StringBuilder' parameters for P/Invokes
        internal static extern int GetSystemDirectory([Out] StringBuilder sb, int length);
#pragma warning restore CA1838 // Avoid 'StringBuilder' parameters for P/Invokes

        [DllImport("api-ms-win-core-sysinfo-l1-1-0.dll")]
        internal static extern ulong GetTickCount64();

        [DllImport("api-ms-win-core-heap-l1-1-0.dll")]
        internal static extern IntPtr GetProcessHeap();

        [DllImport("api-ms-win-core-heap-l1-1-0.dll")]
        internal static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, UIntPtr dwBytes);

        [DllImport("api-ms-win-core-heap-l1-1-0.dll")]
        internal static extern int HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

        internal const int HEAP_ZERO_MEMORY = 0x8;      // Flag to zero memory

        [DllImport("api-ms-win-core-heap-l1-1-0.dll")]
        internal static extern unsafe IntPtr HeapReAlloc(IntPtr hHeap, uint dwFlags, IntPtr lpMem, UIntPtr dwBytes);

        [DllImport(Interop.Libraries.RealTime, EntryPoint = "QueryUnbiasedInterruptTime")]
        private static extern int PInvoke_QueryUnbiasedInterruptTime(out ulong UnbiasedTime);

        internal static bool QueryUnbiasedInterruptTime(out ulong UnbiasedTime)
        {
            int result = PInvoke_QueryUnbiasedInterruptTime(out UnbiasedTime);
            return (result != 0);
        }

        [DllImport("api-ms-win-core-errorhandling-l1-1-0.dll")]
        internal static extern void SetLastError(uint dwErrCode);

        [DllImport(Libraries.Kernel32)]
        internal static extern uint WaitForMultipleObjectsEx(uint nCount, IntPtr lpHandles, bool bWaitAll, uint dwMilliseconds, bool bAlertable);

        [DllImport(Libraries.Kernel32)]
        internal static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport(Libraries.Kernel32)]
        internal static extern uint SignalObjectAndWait(IntPtr hObjectToSignal, IntPtr hObjectToWaitOn, uint dwMilliseconds, bool bAlertable);

        [DllImport(Libraries.Kernel32)]
        internal static extern void Sleep(uint milliseconds);

        [DllImport(Libraries.Kernel32)]
        internal static extern unsafe SafeWaitHandle CreateThread(
            IntPtr lpThreadAttributes,
            IntPtr dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out uint lpThreadId);

        internal delegate uint ThreadProc(IntPtr lpParameter);

        [DllImport(Libraries.Kernel32)]
        internal static extern uint ResumeThread(SafeWaitHandle hThread);

        [DllImport(Libraries.Kernel32)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport(Libraries.Kernel32)]
        internal static extern IntPtr GetCurrentThread();

        [DllImport(Libraries.Kernel32, SetLastError = true)]
        internal static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out SafeWaitHandle lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwOptions);

        internal enum ThreadPriority : int
        {
            Idle = -15,
            Lowest = -2,
            BelowNormal = -1,
            Normal = 0,
            AboveNormal = 1,
            Highest = 2,
            TimeCritical = 15,

            ErrorReturn = 0x7FFFFFFF
        }

        [DllImport(Libraries.Kernel32)]
        internal static extern ThreadPriority GetThreadPriority(SafeWaitHandle hThread);

        [DllImport(Libraries.Kernel32)]
        internal static extern bool SetThreadPriority(SafeWaitHandle hThread, int nPriority);

        internal delegate void WorkCallback(IntPtr Instance, IntPtr Context, IntPtr Work);

        [DllImport("api-ms-win-core-threadpool-l1-2-0.dll")]
        internal static extern IntPtr CreateThreadpoolWork(IntPtr pfnwk, IntPtr pv, IntPtr pcbe);

        [DllImport("api-ms-win-core-threadpool-l1-2-0.dll")]
        internal static extern void SubmitThreadpoolWork(IntPtr pwk);

        [DllImport("api-ms-win-core-threadpool-l1-2-0.dll")]
        internal static extern void CloseThreadpoolWork(IntPtr pwk);

        internal delegate void WaitCallback(IntPtr Instance, IntPtr Context, IntPtr Wait, uint WaitResult);

        [DllImport("api-ms-win-core-threadpool-l1-2-0.dll")]
        internal static extern IntPtr CreateThreadpoolWait(IntPtr pfnwa, IntPtr pv, IntPtr pcbe);

        [DllImport("api-ms-win-core-threadpool-l1-2-0.dll")]
        internal static extern void SetThreadpoolWait(IntPtr pwa, IntPtr h, IntPtr pftTimeout);

        [DllImport("api-ms-win-core-threadpool-l1-2-0.dll")]
        internal static extern void WaitForThreadpoolWaitCallbacks(IntPtr pwa, bool fCancelPendingCallbacks);

        [DllImport("api-ms-win-core-threadpool-l1-2-0.dll")]
        internal static extern void CloseThreadpoolWait(IntPtr pwa);

        [DllImport(Libraries.ThreadPool, SetLastError = true)]
        internal static unsafe extern SafeThreadPoolIOHandle CreateThreadpoolIo(SafeHandle fl, IntPtr pfnio, IntPtr context, IntPtr pcbe);

        [DllImport(Libraries.ThreadPool)]
        internal static unsafe extern void CloseThreadpoolIo(IntPtr pio);

        [DllImport(Libraries.ThreadPool)]
        internal static unsafe extern void StartThreadpoolIo(SafeThreadPoolIOHandle pio);

        [DllImport(Libraries.ThreadPool)]
        internal static unsafe extern void CancelThreadpoolIo(SafeThreadPoolIOHandle pio);

        [DllImport("api-ms-win-core-threadpool-l1-2-0.dll")]
        internal static extern IntPtr CreateThreadpoolTimer(IntPtr pfnti, IntPtr pv, IntPtr pcbe);

        [DllImport("api-ms-win-core-threadpool-l1-2-0.dll")]
        internal static extern unsafe IntPtr SetThreadpoolTimer(IntPtr pti, long* pftDueTime, uint msPeriod, uint msWindowLength);

        internal delegate void TimerCallback(IntPtr Instance, IntPtr Context, IntPtr Timer);

        internal struct SYSTEMTIME
        {
            internal ushort wYear;
            internal ushort wMonth;
            internal ushort wDayOfWeek;
            internal ushort wDay;
            internal ushort wHour;
            internal ushort wMinute;
            internal ushort wSecond;
            internal ushort wMilliseconds;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct TIME_DYNAMIC_ZONE_INFORMATION
        {
            internal int Bias;
            internal fixed char StandardName[32];
            internal SYSTEMTIME StandardDate;
            internal int StandardBias;
            internal fixed char DaylightName[32];
            internal SYSTEMTIME DaylightDate;
            internal int DaylightBias;
            internal fixed char TimeZoneKeyName[128];
            internal byte DynamicDaylightTimeDisabled;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct TIME_ZONE_INFORMATION
        {
            internal int Bias;
            internal fixed char StandardName[32];
            internal SYSTEMTIME StandardDate;
            internal int StandardBias;
            internal fixed char DaylightName[32];
            internal SYSTEMTIME DaylightDate;
            internal int DaylightBias;

            public unsafe TIME_ZONE_INFORMATION(TIME_DYNAMIC_ZONE_INFORMATION dtzi)
            {
                Bias = dtzi.Bias;
                fixed (char* standard = StandardName)
                {
                    for (int i = 0; i < 32; ++i)
                    {
                        standard[i] = dtzi.StandardName[i];
                    }
                }
                fixed (char* daylight = DaylightName)
                {
                    for (int i = 0; i < 32; ++i)
                    {
                        daylight[i] = dtzi.DaylightName[i];
                    }
                }
                StandardDate = dtzi.StandardDate;
                StandardBias = dtzi.StandardBias;
                DaylightDate = dtzi.DaylightDate;
                DaylightBias = dtzi.DaylightBias;
            }
        }

        // TimeZone
        internal const int TIME_ZONE_ID_INVALID = -1;
        internal const int TIME_ZONE_ID_UNKNOWN = 0;
        internal const int TIME_ZONE_ID_STANDARD = 1;
        internal const int TIME_ZONE_ID_DAYLIGHT = 2;

        [DllImport("api-ms-win-core-timezone-l1-1-0.dll")]
        internal static extern uint EnumDynamicTimeZoneInformation(uint dwIndex, out TIME_DYNAMIC_ZONE_INFORMATION lpTimeZoneInformation);

        [DllImport("api-ms-win-core-timezone-l1-1-0.dll")]
        internal static extern uint GetDynamicTimeZoneInformation(out TIME_DYNAMIC_ZONE_INFORMATION pTimeZoneInformation);

        [DllImport("api-ms-win-core-timezone-l1-1-0.dll")]
        internal static extern uint GetDynamicTimeZoneInformationEffectiveYears(ref TIME_DYNAMIC_ZONE_INFORMATION lpTimeZoneInformation, out uint FirstYear, out uint LastYear);

        [DllImport("api-ms-win-core-timezone-l1-1-0.dll")]
        internal static extern bool GetTimeZoneInformationForYear(ushort wYear, ref TIME_DYNAMIC_ZONE_INFORMATION pdtzi, out TIME_ZONE_INFORMATION ptzi);

        [DllImport("api-ms-win-core-timezone-l1-1-0.dll")]
        internal static extern int GetTimeZoneInformation(out TIME_ZONE_INFORMATION lpTimeZoneInformation);

        [DllImport("api-ms-win-core-memory-l1-1-3.dll")]
        internal static extern unsafe void* VirtualAllocFromApp(void* address, UIntPtr numBytes, int commitOrReserve, int pageProtectionMode);
    }

    internal static IntPtr MemAlloc(UIntPtr sizeInBytes)
    {
        IntPtr allocatedMemory = Interop.mincore.HeapAlloc(Interop.mincore.GetProcessHeap(), 0, sizeInBytes);
        if (allocatedMemory == IntPtr.Zero)
        {
            throw new OutOfMemoryException();
        }
        return allocatedMemory;
    }

    internal static void MemFree(IntPtr allocatedMemory)
    {
        Interop.mincore.HeapFree(Interop.mincore.GetProcessHeap(), 0, allocatedMemory);
    }

    internal static IntPtr MemAllocWithZeroInitializeNoThrow(UIntPtr sizeInBytes)
    {
        return Interop.mincore.HeapAlloc(Interop.mincore.GetProcessHeap(), Interop.mincore.HEAP_ZERO_MEMORY, sizeInBytes);
    }

    internal static IntPtr MemReAllocWithZeroInitializeNoThrow(IntPtr ptr, UIntPtr oldSize, UIntPtr newSize)
    {
        return Interop.mincore.HeapReAlloc(Interop.mincore.GetProcessHeap(), Interop.mincore.HEAP_ZERO_MEMORY, ptr, newSize);
    }

    internal static unsafe IntPtr MemReAlloc(IntPtr ptr, UIntPtr newSize)
    {
        IntPtr allocatedMemory = Interop.mincore.HeapReAlloc(Interop.mincore.GetProcessHeap(), 0, ptr, newSize);
        if (allocatedMemory == IntPtr.Zero)
        {
            throw new OutOfMemoryException();
        }
        return allocatedMemory;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate void NativeIoCompletionCallback(IntPtr instance, IntPtr context, IntPtr overlapped, uint ioResult, UIntPtr numberOfBytesTransferred, IntPtr io);

    internal static partial class Libraries
    {
        internal const string ErrorHandling = "api-ms-win-core-errorhandling-l1-1-0.dll";
        internal const string Handle = "api-ms-win-core-handle-l1-1-0.dll";
        internal const string IO = "api-ms-win-core-io-l1-1-0.dll";
        internal const string Memory = "api-ms-win-core-memory-l1-1-0.dll";
        internal const string ProcessEnvironment = "api-ms-win-core-processenvironment-l1-1-0.dll";
        internal const string ProcessThreads = "api-ms-win-core-processthreads-l1-1-0.dll";
        internal const string RealTime = "api-ms-win-core-realtime-l1-1-0.dll";
        internal const string SysInfo = "api-ms-win-core-sysinfo-l1-2-0.dll";
        internal const string ThreadPool = "api-ms-win-core-threadpool-l1-2-0.dll";
        internal const string Localization = "api-ms-win-core-localization-l1-2-1.dll";
    }
}

namespace Internal.Runtime.Augments
{
    internal sealed class RuntimeThread
    {
        // Note: Magic number copied from CoreRT's RuntimeThread.cs. See the original source code for an explanation.
#pragma warning disable CA1802 // Use literals where appropriate
        internal static readonly int OptimalMaxSpinWaitsPerSpinIteration = 64;
#pragma warning restore CA1802 // Use literals where appropriate

        private readonly Thread thread;

        internal RuntimeThread(Thread t) { thread = t; }

        public void ResetThreadPoolThread() { }

#pragma warning disable CS8603 // Possible null reference return.
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
        public static RuntimeThread InitializeThreadPoolThread() => new RuntimeThread(null);
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
#pragma warning restore CS8603 // Possible null reference return.

        public static RuntimeThread Create(ParameterizedThreadStart start, int maxStackSize)
            => new RuntimeThread(new Thread(start, maxStackSize));

        public bool IsBackground
        {
            get => thread.IsBackground;
            set => thread.IsBackground = value;
        }

        public void Start() => thread.Start();

        public void Start(object state) => thread.Start(state);

        public static void Sleep(int millisecondsTimeout) => Thread.Sleep(millisecondsTimeout);

        public static bool Yield() => Thread.Yield();

        public static bool SpinWait(int iterations)
        {
            Thread.SpinWait(iterations);
            return true;
        }

        public static int GetCurrentProcessorId()
        {
            // TODO: Implement correctly
            return 1;
        }
    }
}

namespace System.Threading
{
    /// <summary>
    /// Ensures <c>RuntimeThread.CurrentThread</c> is initialized for a callback running on a thread pool thread.
    /// If WinRT is enabled, also ensures the Windows Runtime is initialized during the execution of the callback.
    /// </summary>
    /// <remarks>
    /// This structure does not implement <c>IDisposable</c> to save on exception support, which callers do not need.
    /// </remarks>
    internal struct ThreadPoolCallbackWrapper
    {
        private RuntimeThread _currentThread;

        public static ThreadPoolCallbackWrapper Enter()
        {
            return new ThreadPoolCallbackWrapper
            {
                _currentThread = RuntimeThread.InitializeThreadPoolThread(),
            };
        }

        public void Exit(bool resetThread = true)
        {
            if (resetThread)
            {
                _currentThread.ResetThreadPoolThread();
            }
        }
    }
}


namespace System.Runtime.InteropServices
{
    internal static class AddrofIntrinsics
    {
        // This method is implemented elsewhere in the toolchain
        internal static IntPtr AddrOf<T>(T ftn)
        {
#pragma warning disable CS8714 // The type cannot be used as type parameter in the generic type or method. Nullability of type argument doesn't match 'notnull' constraint.
            return Marshal.GetFunctionPointerForDelegate<T>(ftn);
#pragma warning restore CS8714 // The type cannot be used as type parameter in the generic type or method. Nullability of type argument doesn't match 'notnull' constraint.
        }
    }
}

namespace System.Threading
{
    //
    // Implementation of ThreadPoolBoundHandle that sits on top of the Win32 ThreadPool
    //
    public sealed class ThreadPoolBoundHandle : IDisposable, IDeferredDisposable
    {
        private readonly SafeHandle _handle;
        private readonly SafeThreadPoolIOHandle _threadPoolHandle;
        private DeferredDisposableLifetime<ThreadPoolBoundHandle> _lifetime;

#if MONO
        static ThreadPoolBoundHandle()
        {
        }
#endif

        private ThreadPoolBoundHandle(SafeHandle handle, SafeThreadPoolIOHandle threadPoolHandle)
        {
            _threadPoolHandle = threadPoolHandle;
            _handle = handle;
        }

        public SafeHandle Handle
        {
            get { return _handle; }
        }

        public static ThreadPoolBoundHandle BindHandle(SafeHandle handle)
        {
            if (handle == null)
                throw new ArgumentNullException(nameof(handle));

            if (handle.IsClosed || handle.IsInvalid)
                throw new ArgumentException(SR.Argument_InvalidHandle, nameof(handle));

            IntPtr callback = AddrofIntrinsics.AddrOf<Interop.NativeIoCompletionCallback>(OnNativeIOCompleted);
            SafeThreadPoolIOHandle threadPoolHandle = Interop.mincore.CreateThreadpoolIo(handle, callback, IntPtr.Zero, IntPtr.Zero);
            if (threadPoolHandle.IsInvalid)
            {
                int errorCode = Marshal.GetLastWin32Error();
                if (errorCode == Interop.Errors.ERROR_INVALID_HANDLE)         // Bad handle
                    throw new ArgumentException(SR.Argument_InvalidHandle, nameof(handle));

                if (errorCode == Interop.Errors.ERROR_INVALID_PARAMETER)     // Handle already bound or sync handle
                    throw new ArgumentException(SR.Argument_AlreadyBoundOrSyncHandle, nameof(handle));

                throw Win32Marshal.GetExceptionForWin32Error(errorCode);
            }

            return new ThreadPoolBoundHandle(handle, threadPoolHandle);
        }


        [CLSCompliant(false)]
        public unsafe NativeOverlapped* UnsafeAllocateNativeOverlapped(IOCompletionCallback callback, object state, object? pinData) =>
            AllocateNativeOverlapped(callback, state, pinData);

        [CLSCompliant(false)]
        public unsafe NativeOverlapped* AllocateNativeOverlapped(IOCompletionCallback callback, object state, object? pinData)
        {
            if (callback == null)
                throw new ArgumentNullException(nameof(callback));

            AddRef();
            try
            {
#pragma warning disable CS8604 // Possible null reference argument.
                Win32ThreadPoolNativeOverlapped* overlapped = Win32ThreadPoolNativeOverlapped.Allocate(callback, state, pinData, preAllocated: null);
#pragma warning restore CS8604 // Possible null reference argument.
                overlapped->Data._boundHandle = this;

                Interop.mincore.StartThreadpoolIo(_threadPoolHandle);

                return Win32ThreadPoolNativeOverlapped.ToNativeOverlapped(overlapped);
            }
            catch
            {
                Release();
                throw;
            }
        }

        [CLSCompliant(false)]
        public unsafe NativeOverlapped* AllocateNativeOverlapped(PreAllocatedOverlapped preAllocated)
        {
            if (preAllocated == null)
                throw new ArgumentNullException(nameof(preAllocated));

            bool addedRefToThis = false;
            bool addedRefToPreAllocated = false;
            try
            {
                addedRefToThis = AddRef();
                addedRefToPreAllocated = preAllocated.AddRef();

                Win32ThreadPoolNativeOverlapped.OverlappedData data = preAllocated._overlapped->Data;
                if (data._boundHandle != null)
                    throw new ArgumentException(SR.Argument_PreAllocatedAlreadyAllocated, nameof(preAllocated));

                data._boundHandle = this;

                Interop.mincore.StartThreadpoolIo(_threadPoolHandle);

                return Win32ThreadPoolNativeOverlapped.ToNativeOverlapped(preAllocated._overlapped);
            }
            catch
            {
                if (addedRefToPreAllocated)
                    preAllocated.Release();
                if (addedRefToThis)
                    Release();
                throw;
            }
        }

        [CLSCompliant(false)]
        public unsafe void FreeNativeOverlapped(NativeOverlapped* overlapped)
        {
            if (overlapped == null)
                throw new ArgumentNullException(nameof(overlapped));

            Win32ThreadPoolNativeOverlapped* threadPoolOverlapped = Win32ThreadPoolNativeOverlapped.FromNativeOverlapped(overlapped);
            Win32ThreadPoolNativeOverlapped.OverlappedData data = GetOverlappedData(threadPoolOverlapped, this);

            if (!data._completed)
            {
                Interop.mincore.CancelThreadpoolIo(_threadPoolHandle);
                Release();
            }

            data._boundHandle = null;
            data._completed = false;

            if (data._preAllocated != null)
                data._preAllocated.Release();
            else
                Win32ThreadPoolNativeOverlapped.Free(threadPoolOverlapped);
        }

        [CLSCompliant(false)]
        public static unsafe object GetNativeOverlappedState(NativeOverlapped* overlapped)
        {
            if (overlapped == null)
                throw new ArgumentNullException(nameof(overlapped));

            Win32ThreadPoolNativeOverlapped* threadPoolOverlapped = Win32ThreadPoolNativeOverlapped.FromNativeOverlapped(overlapped);
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
            Win32ThreadPoolNativeOverlapped.OverlappedData data = GetOverlappedData(threadPoolOverlapped, null);
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.

#pragma warning disable CS8603 // Possible null reference return.
            return data._state;
#pragma warning restore CS8603 // Possible null reference return.
        }

        private static unsafe Win32ThreadPoolNativeOverlapped.OverlappedData GetOverlappedData(Win32ThreadPoolNativeOverlapped* overlapped, ThreadPoolBoundHandle expectedBoundHandle)
        {
            Win32ThreadPoolNativeOverlapped.OverlappedData data = overlapped->Data;

            if (data._boundHandle == null)
                throw new ArgumentException(SR.Argument_NativeOverlappedAlreadyFree, nameof(overlapped));

            if (expectedBoundHandle != null && data._boundHandle != expectedBoundHandle)
                throw new ArgumentException(SR.Argument_NativeOverlappedWrongBoundHandle, nameof(overlapped));

            return data;
        }

        private static unsafe void OnNativeIOCompleted(IntPtr instance, IntPtr context, IntPtr overlappedPtr, uint ioResult, UIntPtr numberOfBytesTransferred, IntPtr ioPtr)
        {
            var wrapper = ThreadPoolCallbackWrapper.Enter();
            Win32ThreadPoolNativeOverlapped* overlapped = (Win32ThreadPoolNativeOverlapped*)overlappedPtr;

#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            ThreadPoolBoundHandle boundHandle = overlapped->Data._boundHandle;
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
            if (boundHandle == null)
                throw new InvalidOperationException(SR.Argument_NativeOverlappedAlreadyFree);

            boundHandle.Release();

            Win32ThreadPoolNativeOverlapped.CompleteWithCallback(ioResult, (uint)numberOfBytesTransferred, overlapped);
            wrapper.Exit();
        }

        private bool AddRef()
        {
            return _lifetime.AddRef();
        }

        private void Release()
        {
            _lifetime.Release(this);
        }

        public void Dispose()
        {
            _lifetime.Dispose(this);
            GC.SuppressFinalize(this);
        }

        ~ThreadPoolBoundHandle()
        {
            //
            // During shutdown, don't automatically clean up, because this instance may still be
            // reachable/usable by other code.
            //
            if (!Environment.HasShutdownStarted)
                ((IDisposable)this).Dispose();
        }

        void IDeferredDisposable.OnFinalRelease(bool disposed)
        {
            if (disposed)
                _threadPoolHandle.Dispose();
        }
    }
}



namespace System.Threading
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct Win32ThreadPoolNativeOverlapped
    {
        // Per-thread cache of the args object, so we don't have to allocate a new one each time.
        [ThreadStatic]
        private static ExecutionContextCallbackArgs t_executionContextCallbackArgs;

        private static ContextCallback s_executionContextCallback;
        private static OverlappedData[] s_dataArray;
        private static int s_dataCount;   // Current number of valid entries in _dataArray
        private static IntPtr s_freeList; // Lock-free linked stack of free ThreadPoolNativeOverlapped instances.

        private NativeOverlapped _overlapped; // must be first, so we can cast to and from NativeOverlapped.
        private IntPtr _nextFree; // if this instance if free, points to the next free instance.
        private int _dataIndex; // Index in _dataArray of this instance's OverlappedData.

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        static Win32ThreadPoolNativeOverlapped()
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        {
        }

        internal OverlappedData Data
        {
            get { return s_dataArray[_dataIndex]; }
        }

        internal static unsafe Win32ThreadPoolNativeOverlapped* Allocate(IOCompletionCallback callback, object state, object pinData, PreAllocatedOverlapped? preAllocated)
        {
            Win32ThreadPoolNativeOverlapped* overlapped = AllocateNew();
            try
            {
                overlapped->SetData(callback, state, pinData, preAllocated);
            }
            catch
            {
                Free(overlapped);
                throw;
            }
            return overlapped;
        }

        private static unsafe Win32ThreadPoolNativeOverlapped* AllocateNew()
        {
            IntPtr freePtr;
            Win32ThreadPoolNativeOverlapped* overlapped;
            OverlappedData data;

            // Find a free Overlapped
            while ((freePtr = Volatile.Read(ref s_freeList)) != IntPtr.Zero)
            {
                overlapped = (Win32ThreadPoolNativeOverlapped*)freePtr;

                if (Interlocked.CompareExchange(ref s_freeList, overlapped->_nextFree, freePtr) != freePtr)
                    continue;

                overlapped->_nextFree = IntPtr.Zero;
                return overlapped;
            }

            // None are free; allocate a new one.
            overlapped = (Win32ThreadPoolNativeOverlapped*)Interop.MemAlloc((UIntPtr)sizeof(Win32ThreadPoolNativeOverlapped));
            *overlapped = default(Win32ThreadPoolNativeOverlapped);

            // Allocate a OverlappedData object, and an index at which to store it in _dataArray.
            data = new OverlappedData();
            int dataIndex = Interlocked.Increment(ref s_dataCount) - 1;

            // Make sure we didn't wrap around.
            if (dataIndex < 0)
                Environment.FailFast("Too many outstanding Win32ThreadPoolNativeOverlapped instances");

            while (true)
            {
                OverlappedData[] dataArray = Volatile.Read(ref s_dataArray);
                int currentLength = dataArray == null ? 0 : dataArray.Length;

                // If the current array is too small, create a new, larger one.
                if (currentLength <= dataIndex)
                {
                    int newLength = currentLength;
                    if (newLength == 0)
                        newLength = 128;
                    while (newLength <= dataIndex)
                        newLength = (newLength * 3) / 2;

#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
                    OverlappedData[] newDataArray = dataArray;
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
                    Array.Resize(ref newDataArray, newLength);

                    if (Interlocked.CompareExchange(ref s_dataArray, newDataArray, dataArray) != dataArray)
                        continue; // Someone else got the free one, try again

                    dataArray = newDataArray;
                }

                // If we haven't stored this object in the array yet, do so now.  Then we need to make another pass through
                // the loop, in case another thread resized the array before we made this update.
                if (s_dataArray[dataIndex] == null)
                {
                    // Full fence so this write can't move past subsequent reads.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                    _ = Interlocked.Exchange(ref dataArray[dataIndex], data);
#pragma warning restore CS8602 // Dereference of a possibly null reference.
                    continue;
                }

                // We're already in the array, so we're done.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                Debug.Assert(dataArray[dataIndex] == data);
#pragma warning restore CS8602 // Dereference of a possibly null reference.
                overlapped->_dataIndex = dataIndex;
                return overlapped;
            }
        }

        private void SetData(IOCompletionCallback callback, object state, object? pinData, PreAllocatedOverlapped? preAllocated)
        {
            Debug.Assert(callback != null);

            OverlappedData data = Data;

            data._callback = callback;
            data._state = state;
            data._executionContext = ExecutionContext.Capture();
            data._preAllocated = preAllocated;

            //
            // pinData can be any blittable type to be pinned, *or* an instance of object[] each element of which refers to
            // an instance of a blittable type to be pinned.
            //
            if (pinData is object[] objArray)
            {
                if (objArray != null && objArray.GetType() == typeof(object[]))
                {
                    if (data._pinnedData == null || data._pinnedData.Length < objArray.Length)
                        Array.Resize(ref data._pinnedData, objArray.Length);

                    for (int i = 0; i < objArray.Length; i++)
                    {
                        if (!data._pinnedData[i].IsAllocated)
                            data._pinnedData[i] = GCHandle.Alloc(objArray[i], GCHandleType.Pinned);
                        else
                            data._pinnedData[i].Target = objArray[i];
                    }
                }
                else
                {
                    if (data._pinnedData == null)
                        data._pinnedData = new GCHandle[1];

                    if (!data._pinnedData[0].IsAllocated)
                        data._pinnedData[0] = GCHandle.Alloc(pinData, GCHandleType.Pinned);
                    else
                        data._pinnedData[0].Target = pinData;
                }
            }
        }

        internal static unsafe void Free(Win32ThreadPoolNativeOverlapped* overlapped)
        {
            // Reset all data.
            overlapped->Data.Reset();
            overlapped->_overlapped = default(NativeOverlapped);

            // Add to the free list.
            while (true)
            {
                IntPtr freePtr = Volatile.Read(ref s_freeList);
                overlapped->_nextFree = freePtr;

                if (Interlocked.CompareExchange(ref s_freeList, (IntPtr)overlapped, freePtr) == freePtr)
                    break;
            }
        }

        internal static unsafe NativeOverlapped* ToNativeOverlapped(Win32ThreadPoolNativeOverlapped* overlapped)
        {
            return (NativeOverlapped*)overlapped;
        }

        internal static unsafe Win32ThreadPoolNativeOverlapped* FromNativeOverlapped(NativeOverlapped* overlapped)
        {
            return (Win32ThreadPoolNativeOverlapped*)overlapped;
        }

        internal static unsafe void CompleteWithCallback(uint errorCode, uint bytesWritten, Win32ThreadPoolNativeOverlapped* overlapped)
        {
            OverlappedData data = overlapped->Data;

            Debug.Assert(!data._completed);
            data._completed = true;

            if (data._executionContext == null)
            {
                data._callback?.Invoke(errorCode, bytesWritten, ToNativeOverlapped(overlapped));
                return;
            }

            ContextCallback callback = s_executionContextCallback;
            if (callback == null)
#pragma warning disable CS8622 // Nullability of reference types in type of parameter doesn't match the target delegate (possibly because of nullability attributes).
                s_executionContextCallback = callback = OnExecutionContextCallback;
#pragma warning restore CS8622 // Nullability of reference types in type of parameter doesn't match the target delegate (possibly because of nullability attributes).

            // Get an args object from the per-thread cache.
            ExecutionContextCallbackArgs args = t_executionContextCallbackArgs;
            if (args == null)
                args = new ExecutionContextCallbackArgs();

#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
            t_executionContextCallbackArgs = null;
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.

            args._errorCode = errorCode;
            args._bytesWritten = bytesWritten;
            args._overlapped = overlapped;
            args._data = data;

            ExecutionContext.Run(data._executionContext, callback, args);
        }

        private static unsafe void OnExecutionContextCallback(object state)
        {
            ExecutionContextCallbackArgs args = (ExecutionContextCallbackArgs)state;

            uint errorCode = args._errorCode;
            uint bytesWritten = args._bytesWritten;
            Win32ThreadPoolNativeOverlapped* overlapped = args._overlapped;
            OverlappedData data = args._data;

            // Put the args object back in the per-thread cache, now that we're done with it.
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
            args._data = null;
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
            t_executionContextCallbackArgs = args;

#pragma warning disable CS8602 // Dereference of a possibly null reference.
            data._callback(errorCode, bytesWritten, ToNativeOverlapped(overlapped));
#pragma warning restore CS8602 // Dereference of a possibly null reference.
        }
    }
}

namespace System.Threading
{
    internal partial struct Win32ThreadPoolNativeOverlapped
    {
        private unsafe class ExecutionContextCallbackArgs
        {
            internal uint _errorCode;
            internal uint _bytesWritten;
            internal Win32ThreadPoolNativeOverlapped* _overlapped;
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
            internal OverlappedData _data;
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        }
    }
}




namespace System.Threading
{
    internal partial struct Win32ThreadPoolNativeOverlapped
    {
        internal class OverlappedData
        {
            internal GCHandle[]? _pinnedData;
            internal IOCompletionCallback? _callback;
            internal object? _state;
            internal ExecutionContext? _executionContext;
            internal ThreadPoolBoundHandle? _boundHandle;
            internal PreAllocatedOverlapped? _preAllocated;
            internal bool _completed;

            internal void Reset()
            {
                Debug.Assert(_boundHandle == null); //not in use

                if (_pinnedData != null)
                {
                    for (int i = 0; i < _pinnedData.Length; i++)
                    {
                        if (_pinnedData[i].IsAllocated && _pinnedData[i].Target != null)
                            _pinnedData[i].Target = null;
                    }
                }

                _callback = null;
                _state = null;
                _executionContext = null;
                _completed = false;
                _preAllocated = null;
            }
        }
    }
}

namespace System.Threading
{
    public sealed partial class PreAllocatedOverlapped : IDisposable, IDeferredDisposable
    {
        internal unsafe readonly Win32ThreadPoolNativeOverlapped* _overlapped;
        private DeferredDisposableLifetime<PreAllocatedOverlapped> _lifetime;

        static PreAllocatedOverlapped()
        {
        }

        [CLSCompliantAttribute(false)]
#pragma warning disable CS8604 // Possible null reference argument.
        public static PreAllocatedOverlapped UnsafeCreate(IOCompletionCallback callback, object? state, object? pinData) => new PreAllocatedOverlapped(callback, state, pinData);
#pragma warning restore CS8604 // Possible null reference argument.

        internal bool IsUserObject(byte[]? buffer) => false;

        [CLSCompliant(false)]
        public unsafe PreAllocatedOverlapped(IOCompletionCallback callback, object state, object pinData)
        {
            if (callback == null)
                throw new ArgumentNullException(nameof(callback));

            _overlapped = Win32ThreadPoolNativeOverlapped.Allocate(callback, state, pinData, this);
        }

        internal bool AddRef()
        {
            return _lifetime.AddRef();
        }

        internal void Release()
        {
            _lifetime.Release(this);
        }

        public void Dispose()
        {
            _lifetime.Dispose(this);
            GC.SuppressFinalize(this);
        }

        ~PreAllocatedOverlapped()
        {
            //
            // During shutdown, don't automatically clean up, because this instance may still be
            // reachable/usable by other code.
            //
            if (!Environment.HasShutdownStarted)
                ((IDisposable)this).Dispose();
        }

        unsafe void IDeferredDisposable.OnFinalRelease(bool disposed)
        {
            if (_overlapped != null)
            {
                if (disposed)
                    Win32ThreadPoolNativeOverlapped.Free(_overlapped);
                else
                    *Win32ThreadPoolNativeOverlapped.ToNativeOverlapped(_overlapped) = default(NativeOverlapped);
            }
        }
    }
}
