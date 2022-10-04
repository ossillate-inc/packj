# http://stackoverflow.com/questions/13044562/python-mechanism-to-identify-compressed-file-type-and-uncompress
# All the magic numbers for file types: http://www.garykessler.net/library/file_sigs.html
import zipfile
import tarfile
import rarfile
import logging
import tempfile
import shutil
import magic
import bz2
import gzip
import sys
import os

from os.path import abspath, basename, splitext

# python 3.3+
try:
    import lzma
except:
    logging.info("Using Python 2.7 and lzma is not available!")

import tarfile
import os.path

def make_tarfile(output_filename, source_dir):
	with tarfile.open(output_filename, "w:gz") as tar:
		tar.add(source_dir, arcname=os.path.basename(source_dir))

class CompressedFile (object):
    magic = None
    file_type = None
    mime_type = None
    proper_extension = None

    def __init__(self, f):
        # f is an open file or file like object
        self.f = f
        self.accessor = self.open()

    @classmethod
    def is_magic(self, data):
        return data.startswith(self.magic.encode('UTF-8'))

    def open(self):
        return None


class ZIPFile (CompressedFile):
    magic = '\x50\x4b\x03\x04'
    file_type = 'zip'
    mime_type = 'compressed/zip'

    def open(self):
        return zipfile.ZipFile(self.f)


class BZ2File (CompressedFile):
    magic = '\x42\x5a\x68'
    file_type = 'bz2'
    mime_type = 'compressed/bz2'

    def open(self):
        return bz2.BZ2File(self.f)


class GZFile (CompressedFile):
    magic = '\x1f\x8b\x08'
    file_type = 'gz'
    mime_type = 'compressed/gz'

    def open(self):
        return gzip.GzipFile(self.f)


class SevenZFile (CompressedFile):
    magic = '\x37\x7A\xBC\xAF\x27\x1C'
    file_type = '7z'
    mime_type = 'compressed/7z'

    def open(self):
        raise Exception("Unhandled mime_type: %s" % self.mime_type)
        return None


class TarFile (CompressedFile):
    magic = '\x75\x73\x74\x61\x72'
    file_type = 'tar'
    mime_type = 'compressed/tar'

    def open(self):
        return tarfile.TarFile(self.f)


class XZFile (CompressedFile):
    # This only works in python 3.3+
    magic = '\xFD\x37\x7A\x58\x5A\x00'
    file_type = 'xz'
    mime_type = 'compressed/xz'

    def open(self):
        return lzma.LZMAFile(self.f)


class JARCSFile (CompressedFile):
    magic = '\x4A\x41\x52\x43\x53\x00'
    file_type = 'jarcs'
    mime_type = 'compressed/jarcs'

    def open(self):
        raise Exception("Unhandled file type: %s" % self.file_type)


class MARFile (CompressedFile):
    magic = '\x4D\x41\x52\x31\x00'
    file_type = 'mar'
    mime_type = 'compressed/mar'

    def open(self):
        raise Exception("Unhandled file type: %s" % self.file_type)


class RARFile (CompressedFile):
    magic = '\x52\x61\x72\x21\x1A\x07'  # 52 61 72 21 1A 07 00, RAR (V4.x), 52 61 72 21 1A 07 01 00, RAR (V5)
    file_type = 'rar'
    mime_type = 'compressed/rar'

    def open(self):
        return rarfile.RarFile(self.f)


class WinZIPFile (CompressedFile):
    magic = '\x57\x69\x6E\x5A\x69\x70'
    file_type = 'winzip'
    mime_type = 'compressed/winzip'

    def open(self):
        return zipfile.ZipFile(self.f)


# This is used for decompression
MIME_TO_ZIPTYPE_FOR_DECOMPRESSION = {
    'application/zip': ZIPFile,  # This may have false positive
    'application/x-bzip2': BZ2File,
    'application/bzip2': BZ2File,
    'application/x-gzip': GZFile,
    'application/gzip': GZFile,
    'application/x-tar': TarFile,
    'application/tar': TarFile,
    'application/x-xz': XZFile,
    'application/xz': XZFile,
}


# factory function to create a suitable instance for accessing files
def get_compressed_file(filename):
    f = open(filename, 'rb')
    start_of_file = f.read(1024)
    f.seek(0)
    for cls in (ZIPFile, BZ2File, GZFile, SevenZFile, TarFile, XZFile, JARCSFile, MARFile, RARFile, WinZIPFile):
        if cls.is_magic(start_of_file):
            if cls in (GZFile, BZ2File, TarFile):
                return cls(filename)
            else:
                return cls(f)
    return None


def get_file_with_meta(filepath):
    file_with_meta = get_compressed_file(filepath)
    if file_with_meta is None:
        logging.debug('%s: get_compressed_file failed, trying get_mime_for_file for decompression!', filepath)
        file_mime = magic.from_file(filepath, mime=True)
        if file_mime in MIME_TO_ZIPTYPE_FOR_DECOMPRESSION:
            file_with_meta = MIME_TO_ZIPTYPE_FOR_DECOMPRESSION[file_mime](filepath)
        else:
            logging.warning("Unhandled file mime: %s", file_mime)
            return None
    return file_with_meta


def decompress_file(filename):
    # NOTE: the caller is responsible for removing the extracted directory
    filepath = abspath(filename)
    file_with_meta = get_file_with_meta(filepath)
    if file_with_meta is None:
        return None

    file_obj = file_with_meta.accessor
    # decompress to extract_dir
    extract_dir = tempfile.mkdtemp(prefix='decompress-')
    if hasattr(file_obj, 'extractall'):
        #logging.warning("writing content to %s", extract_dir)
        file_obj.extractall(extract_dir)
    else:
        if file_with_meta.file_type in ('gz', 'bz2'):
            temp_filename = os.path.join(extract_dir, splitext(basename(filepath))[0])
            logging.debug("writing content to %s", temp_filename)
            open(temp_filename, 'wb').write(file_obj.read())

            # if the extracted file is again compressed
            if get_file_with_meta(temp_filename) is not None:
                new_extract_dir = decompress_file(temp_filename)
                shutil.rmtree(extract_dir)
                extract_dir = new_extract_dir
        else:
            logging.error("unhandled compressed file format: %s", file_with_meta.file_type)
    return extract_dir


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise Exception("python compress_files.py $compressed_filename")
    filename = sys.argv[1]
    cf = get_compressed_file(filename)
    if cf is not None:
        print(filename, 'is a', cf.mime_type, 'file')
        print(cf.accessor)
