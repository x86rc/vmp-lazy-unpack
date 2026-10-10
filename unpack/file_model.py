from .pe import align_up, memory_image


class FileModel:
    def __init__(self, uc, files, next_view=0x31000000000):
        self.uc = uc
        self.files = {name.lower(): data for name, data in files.items()}
        self.handles = {}
        self.next_handle = 0x2000
        self.next_view = next_view
        self.views = {}

    def handle(self, record):
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = record
        return handle

    def open(self, path):
        name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if name not in self.files:
            return None
        return self.handle({"kind": "file", "name": name, "data": self.files[name]})

    def section(self, handle, attributes):
        record = self.handles.get(handle)
        if record is None or record["kind"] != "file":
            return None
        data = record["data"]
        image = bool(attributes & 0x1000000)
        if image:
            data = memory_image(data)
        return self.handle({"kind": "section", "name": record["name"], "data": data, "image": image})

    def map(self, handle, offset=0, requested_size=0):
        record = self.handles.get(handle)
        if record is None or record["kind"] != "section":
            raise ValueError("invalid section handle")
        if offset != 0:
            raise ValueError("nonzero section offsets not supported")
        size = align_up(len(record["data"]), 4096)
        if sum(view["size"] for view in self.views.values()) + size > 512 * 1024 * 1024:
            raise ValueError("file mapping limit exceeded")
        if requested_size and requested_size != size:
            raise ValueError("partial section views not supported")
        address = self.next_view
        self.next_view += align_up(size, 65536) + 65536
        self.uc.mem_map(address, size)
        self.uc.mem_write(address, record["data"])
        self.views[address] = {"size": size, "name": record["name"], "image": record["image"]}
        return address, size
