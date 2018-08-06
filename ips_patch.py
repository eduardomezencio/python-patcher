"""Classes that represent an IPS patch."""

import operator

BYTEORDER = 'big'
OFFSET_SIZE = 3
OFFSET_BITS = OFFSET_SIZE * 8
OFFSET_MAX = 2 ** OFFSET_BITS - 1
SIZE_SIZE = 2
SIZE_BITS = SIZE_SIZE * 8
SIZE_MAX = 2 ** SIZE_BITS - 1
RLE_SIZE_SIZE = 2
RLE_SIZE_BITS = RLE_SIZE_SIZE * 8
RLE_SIZE_MAX = 2 ** RLE_SIZE_BITS - 1
PATCH = b'PATCH'
EOF = b'EOF'


class IPSPatchRecord:
    """Record from an IPS patch."""
    def __init__(self, offset: int, data: bytes, rle_size: int = 0):
        if not 0 <= offset <= OFFSET_MAX:
            raise ValueError(f'Offset must be a {OFFSET_BITS} bit '
                             'unsigned value.')
        self.offset = offset
        if len(data) > SIZE_MAX:
            raise ValueError(f'Record data size should fit in {SIZE_BITS} '
                             'bits.')
        self.data = bytes(data)
        if not 0 <= rle_size <= RLE_SIZE_MAX:
            raise ValueError(F'RLE size must be a {RLE_SIZE_BITS} bit '
                             'unsigned value.')
        self.rle_size = rle_size

    @property
    def is_rle(self):
        """If the record is RLE encoded."""
        return self.rle_size > 0

    @property
    def size(self):
        """Value in the size field of the record."""
        return 0 if self.is_rle else len(self.data)

    @property
    def applied_size(self):
        """Number of bytes changed by this record."""
        return self.rle_size if self.is_rle else self.size

    @staticmethod
    def from_bytes(data: bytes):
        """Creates a PatchRecord from bytes."""
        i = 0
        record = {}
        record['offset'] = int.from_bytes(data[i:i+OFFSET_SIZE], BYTEORDER)
        i += OFFSET_SIZE
        size = int.from_bytes(data[i:i+SIZE_SIZE], BYTEORDER)
        i += SIZE_SIZE
        if size > 0:
            record['rle_size'] = 0
            record['data'] = bytes(data[i:i+size])
        else:
            record['rle_size'] = int.from_bytes(data[i:i+RLE_SIZE_SIZE],
                                                BYTEORDER)
            i += RLE_SIZE_SIZE
            record['data'] = bytes(data[i:i+1])
        return IPSPatchRecord(**record)

    def to_bytes(self):
        """Get binary representation of the record."""
        data = bytearray()
        data += self.offset.to_bytes(OFFSET_SIZE, BYTEORDER)
        if self.is_rle:
            data += b'\x00' * SIZE_SIZE
            data += self.rle_size.to_bytes(RLE_SIZE_SIZE, BYTEORDER)
            data += self.data[:1] * self.rle_size
        else:
            data += len(self.data).to_bytes(SIZE_SIZE, BYTEORDER)
            data += self.data
        return data

    def apply(self, data: bytearray):
        """Apply this record to the data, mutating the given object."""
        i = self.offset
        if self.is_rle:
            data[i:i+self.rle_size] = self.data[:1] * self.rle_size
        else:
            data[i:i+self.size] = self.data

    def __len__(self):
        """The number of bytes in binary format."""
        if self.is_rle:
            return OFFSET_SIZE + SIZE_SIZE + RLE_SIZE_SIZE + 1

        return OFFSET_SIZE + SIZE_SIZE + len(self.data)

    def __str__(self):
        return (f'{self.__class__.__name__}: '
                f'{hex(self.applied_size)} bytes from '
                f'{hex(self.offset)}'
                f'{" (RLE)" if self.is_rle else ""}')


class IPSPatch:
    """IPS patch."""
    def __init__(self):
        self.records = []

    @staticmethod
    def from_bytes(data: bytes):
        """Creates an IPSPatch from bytes."""
        patch = IPSPatch()
        i = 0
        if data[i:i+len(PATCH)] != PATCH:
            raise ValueError('Invalid patch format.')
        i += len(PATCH)
        while data[i:i+len(EOF)] != EOF:
            view = memoryview(data)[i:]
            if not view:
                raise ValueError('Invalid patch format.')
            patch.records.append(IPSPatchRecord.from_bytes(view))
            i += len(patch.records[-1])
        return patch

    def to_bytes(self):
        """Get the binary representation of the patch."""
        data = bytearray()
        data += PATCH
        for record in self.records:
            data += record.to_bytes()
        data += EOF
        return data

    @staticmethod
    def from_diff(src: bytes, dest: bytes):
        """Create an IPSPatch from source and destination data, finding the
        differences between them."""
        sview, dview = memoryview(src), memoryview(dest)

        def find_first(start, end, comp):
            """Find index of first bytes to return true with comp."""
            return next(filter(
                lambda x: comp(*x[1]),
                enumerate(zip(sview[start:end], dview[start:end]), start)
            ), [end])[0]

        patch = IPSPatch()
        i = diff_start = find_first(0, len(src), operator.ne)
        while i < len(src):
            i = diff_end = find_first(i, min(len(src), i + SIZE_MAX),
                                      operator.eq)
            patch.records.append(IPSPatchRecord(diff_start,
                                                dview[diff_start:diff_end]))
            i = diff_start = find_first(i, len(src), operator.ne)
        while i < len(dest):
            i = diff_end = min(len(dest), i + SIZE_MAX)
            patch.records.append(IPSPatchRecord(diff_start,
                                                dview[diff_start:diff_end]))
            diff_start = i
        return patch

    def apply(self, data: bytearray, mutate: bool = False):
        """Apply patch to binary data. If mutate is true, mutates the data
        object, otherwise returns a patched copy.
        """
        if not mutate:
            data = bytearray(data)
        for record in self.records:
            record.apply(data)
        return data if not mutate else None

    @staticmethod
    def from_file(filename: str):
        """Creates an IPSPatch from a file."""
        with open(filename, 'rb') as file:
            return IPSPatch.from_bytes(file.read())

    def to_file(self, filename: str):
        """Writes the patch to a file."""
        with open(filename, 'wb') as file:
            file.write(self.to_bytes())
