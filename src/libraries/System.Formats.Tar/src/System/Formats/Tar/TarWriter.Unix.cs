// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace System.Formats.Tar
{
    // Unix specific methods for the TarWriter class.
    public sealed partial class TarWriter : IDisposable
    {
        private readonly Dictionary<uint, string> _userIdentifiers = new Dictionary<uint, string>();
        private readonly Dictionary<uint, string> _groupIdentifiers = new Dictionary<uint, string>();

        // Unix specific implementation of the method that reads an entry from disk and writes it into the archive stream.
        partial void ReadFileFromDiskAndWriteToArchiveStreamAsEntry(string fullPath, string entryName)
        {
            Interop.Sys.FileStatus status = default;
            status.Mode = default;
            status.Dev = default;
            Interop.CheckIo(Interop.Sys.LStat(fullPath, out status));

            TarEntryType entryType = (status.Mode & (uint)Interop.Sys.FileTypes.S_IFMT) switch
            {
                // Hard links are treated as regular files.
                // Unix socket files do not get added to tar files.
                Interop.Sys.FileTypes.S_IFBLK => TarEntryType.BlockDevice,
                Interop.Sys.FileTypes.S_IFCHR => TarEntryType.CharacterDevice,
                Interop.Sys.FileTypes.S_IFIFO => TarEntryType.Fifo,
                Interop.Sys.FileTypes.S_IFLNK => TarEntryType.SymbolicLink,
                Interop.Sys.FileTypes.S_IFREG => Format is TarEntryFormat.V7 ? TarEntryType.V7RegularFile : TarEntryType.RegularFile,
                Interop.Sys.FileTypes.S_IFDIR => TarEntryType.Directory,
                _ => throw new IOException(string.Format(SR.TarUnsupportedFile, fullPath)),
            };

            FileSystemInfo info = entryType is TarEntryType.Directory ? new DirectoryInfo(fullPath) : new FileInfo(fullPath);

            TarEntry entry = Format switch
            {
                TarEntryFormat.V7 => new V7TarEntry(entryType, entryName),
                TarEntryFormat.Ustar => new UstarTarEntry(entryType, entryName),
                TarEntryFormat.Pax => new PaxTarEntry(entryType, entryName),
                TarEntryFormat.Gnu => new GnuTarEntry(entryType, entryName),
                _ => throw new FormatException(string.Format(SR.TarInvalidFormat, Format)),
            };

            if (entryType is TarEntryType.BlockDevice or TarEntryType.CharacterDevice)
            {
                uint major;
                uint minor;
                unsafe
                {
                    Interop.Sys.GetDeviceIdentifiers((ulong)status.RDev, &major, &minor);
                }

                entry._header._devMajor = (int)major;
                entry._header._devMinor = (int)minor;
            }

            entry._header._mTime = info.LastWriteTimeUtc;
            entry._header._aTime = info.LastAccessTimeUtc;
            // FileSystemInfo does not have ChangeTime, but LastWriteTime and LastAccessTime make sure to add nanoseconds, so we should do the same here
            entry._header._cTime = DateTimeOffset.FromUnixTimeSeconds(status.CTime).AddTicks(status.CTimeNsec / 100 /* nanoseconds per tick */);

            entry._header._mode = (status.Mode & 4095); // First 12 bits

            // Uid and UName
            entry._header._uid = (int)status.Uid;
            if (!_userIdentifiers.TryGetValue(status.Uid, out string? uName))
            {
                uName = Interop.Sys.GetUserNameFromPasswd(status.Uid);
                _userIdentifiers.Add(status.Uid, uName);
            }
            entry._header._uName = uName;

            // Gid and GName
            entry._header._gid = (int)status.Gid;
            if (!_groupIdentifiers.TryGetValue(status.Gid, out string? gName))
            {
                gName = Interop.Sys.GetGroupName(status.Gid);
                _groupIdentifiers.Add(status.Gid, gName);
            }
            entry._header._gName = gName;

            if (entry.EntryType == TarEntryType.SymbolicLink)
            {
                entry.LinkName = info.LinkTarget ?? string.Empty;
            }

            if (entry.EntryType is TarEntryType.RegularFile or TarEntryType.V7RegularFile)
            {
                Debug.Assert(entry._header._dataStream == null);
                entry._header._dataStream = File.OpenRead(fullPath);
            }

            WriteEntry(entry);
            if (entry._header._dataStream != null)
            {
                entry._header._dataStream.Dispose();
            }
        }
    }
}
