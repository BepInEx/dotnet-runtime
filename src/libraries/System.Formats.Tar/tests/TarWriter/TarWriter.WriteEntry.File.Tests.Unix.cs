﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.DotNet.RemoteExecutor;
using System.IO;
using Xunit;

namespace System.Formats.Tar.Tests
{
    public partial class TarWriter_WriteEntry_File_Tests : TarTestsBase
    {
        private static bool IsRemoteExecutorSupportedAndOnUnixAndSuperUser => RemoteExecutor.IsSupported && PlatformDetection.IsUnixAndSuperUser;

        [ConditionalTheory(nameof(IsRemoteExecutorSupportedAndOnUnixAndSuperUser))]
        [InlineData(TarEntryFormat.Ustar)]
        [InlineData(TarEntryFormat.Pax)]
        [InlineData(TarEntryFormat.Gnu)]
        public void Add_Fifo(TarEntryFormat format)
        {
            RemoteExecutor.Invoke((string strFormat) =>
            {
                TarEntryFormat expectedFormat = Enum.Parse<TarEntryFormat>(strFormat);

                using TempDirectory root = new TempDirectory();
                string fifoName = "fifofile";
                string fifoPath = Path.Join(root.Path, fifoName);

                Interop.CheckIo(Interop.Sys.MkFifo(fifoPath, (int)DefaultMode));

                using MemoryStream archive = new MemoryStream();
                using (TarWriter writer = new TarWriter(archive, expectedFormat, leaveOpen: true))
                {
                    writer.WriteEntry(fileName: fifoPath, entryName: fifoName);
                }

                archive.Seek(0, SeekOrigin.Begin);
                using (TarReader reader = new TarReader(archive))
                {
                    PosixTarEntry entry = reader.GetNextEntry() as PosixTarEntry;
                    Assert.Equal(expectedFormat, entry.Format);

                    Assert.NotNull(entry);
                    Assert.Equal(fifoName, entry.Name);
                    Assert.Equal(DefaultLinkName, entry.LinkName);
                    Assert.Equal(TarEntryType.Fifo, entry.EntryType);
                    Assert.Null(entry.DataStream);

                    VerifyPlatformSpecificMetadata(fifoPath, entry);

                    Assert.Null(reader.GetNextEntry());
                }

            }, format.ToString(), new RemoteInvokeOptions { RunAsSudo = true }).Dispose();
        }

        [ConditionalTheory(nameof(IsRemoteExecutorSupportedAndOnUnixAndSuperUser))]
        [InlineData(TarEntryFormat.Ustar)]
        [InlineData(TarEntryFormat.Pax)]
        [InlineData(TarEntryFormat.Gnu)]
        public void Add_BlockDevice(TarEntryFormat format)
        {
            RemoteExecutor.Invoke((string strFormat) =>
            {
                TarEntryFormat expectedFormat = Enum.Parse<TarEntryFormat>(strFormat);

                using TempDirectory root = new TempDirectory();
                string blockDevicePath = Path.Join(root.Path, AssetBlockDeviceFileName);

                // Creating device files needs elevation
                Interop.CheckIo(Interop.Sys.CreateBlockDevice(blockDevicePath, (int)DefaultMode, TestBlockDeviceMajor, TestBlockDeviceMinor));

                using MemoryStream archive = new MemoryStream();
                using (TarWriter writer = new TarWriter(archive, expectedFormat, leaveOpen: true))
                {
                    writer.WriteEntry(fileName: blockDevicePath, entryName: AssetBlockDeviceFileName);
                }

                archive.Seek(0, SeekOrigin.Begin);
                using (TarReader reader = new TarReader(archive))
                {
                    PosixTarEntry entry = reader.GetNextEntry() as PosixTarEntry;
                    Assert.Equal(expectedFormat, entry.Format);

                    Assert.NotNull(entry);
                    Assert.Equal(AssetBlockDeviceFileName, entry.Name);
                    Assert.Equal(DefaultLinkName, entry.LinkName);
                    Assert.Equal(TarEntryType.BlockDevice, entry.EntryType);
                    Assert.Null(entry.DataStream);

                    VerifyPlatformSpecificMetadata(blockDevicePath, entry);

                    Assert.Equal(TestBlockDeviceMajor, entry.DeviceMajor);
                    Assert.Equal(TestBlockDeviceMinor, entry.DeviceMinor);

                    Assert.Null(reader.GetNextEntry());
                }

            }, format.ToString(), new RemoteInvokeOptions { RunAsSudo = true }).Dispose();
        }

        [ConditionalTheory(nameof(IsRemoteExecutorSupportedAndOnUnixAndSuperUser))]
        [InlineData(TarEntryFormat.Ustar)]
        [InlineData(TarEntryFormat.Pax)]
        [InlineData(TarEntryFormat.Gnu)]
        public void Add_CharacterDevice(TarEntryFormat format)
        {
            RemoteExecutor.Invoke((string strFormat) =>
            {
                TarEntryFormat expectedFormat = Enum.Parse<TarEntryFormat>(strFormat);
                using TempDirectory root = new TempDirectory();
                string characterDevicePath = Path.Join(root.Path, AssetCharacterDeviceFileName);

                // Creating device files needs elevation
                Interop.CheckIo(Interop.Sys.CreateCharacterDevice(characterDevicePath, (int)DefaultMode, TestCharacterDeviceMajor, TestCharacterDeviceMinor));

                using MemoryStream archive = new MemoryStream();
                using (TarWriter writer = new TarWriter(archive, expectedFormat, leaveOpen: true))
                {
                    writer.WriteEntry(fileName: characterDevicePath, entryName: AssetCharacterDeviceFileName);
                }

                archive.Seek(0, SeekOrigin.Begin);
                using (TarReader reader = new TarReader(archive))
                {
                    PosixTarEntry entry = reader.GetNextEntry() as PosixTarEntry;
                    Assert.Equal(expectedFormat, entry.Format);

                    Assert.NotNull(entry);
                    Assert.Equal(AssetCharacterDeviceFileName, entry.Name);
                    Assert.Equal(DefaultLinkName, entry.LinkName);
                    Assert.Equal(TarEntryType.CharacterDevice, entry.EntryType);
                    Assert.Null(entry.DataStream);

                    VerifyPlatformSpecificMetadata(characterDevicePath, entry);

                    Assert.Equal(TestCharacterDeviceMajor, entry.DeviceMajor);
                    Assert.Equal(TestCharacterDeviceMinor, entry.DeviceMinor);

                    Assert.Null(reader.GetNextEntry());
                }

            }, format.ToString(), new RemoteInvokeOptions { RunAsSudo = true }).Dispose();
        }

        partial void VerifyPlatformSpecificMetadata(string filePath, TarEntry entry)
        {
            Interop.Sys.FileStatus status = default;
            status.Mode = default;
            status.Dev = default;
            Interop.CheckIo(Interop.Sys.LStat(filePath, out status));

            Assert.Equal((int)status.Uid, entry.Uid);
            Assert.Equal((int)status.Gid, entry.Gid);

            if (entry is PosixTarEntry posix)
            {
                string gname = Interop.Sys.GetGroupName(status.Gid);
                string uname = Interop.Sys.GetUserNameFromPasswd(status.Uid);

                Assert.Equal(gname, posix.GroupName);
                Assert.Equal(uname, posix.UserName);

                if (entry.EntryType is not TarEntryType.BlockDevice and not TarEntryType.CharacterDevice)
                {
                    Assert.Equal(DefaultDeviceMajor, posix.DeviceMajor);
                    Assert.Equal(DefaultDeviceMinor, posix.DeviceMinor);
                }
            }

            if (entry.EntryType is not TarEntryType.Directory)
            {
                TarFileMode expectedMode = (TarFileMode)(status.Mode & 4095); // First 12 bits
               
                Assert.Equal(expectedMode, entry.Mode);
                Assert.True(entry.ModificationTime > DateTimeOffset.UnixEpoch);

                if (entry is PaxTarEntry pax)
                {
                    VerifyPaxTimestamps(pax);
                }

                if (entry is GnuTarEntry gnu)
                {
                    VerifyGnuTimestamps(gnu);
                }
            }
        }
    }
}
