from dataclasses import dataclass


# The Document dataclass stores the progress data
# sent by Koreader for each book.
@dataclass
class Document:
    document: str
    progress: str
    percentage: float
    device: str
    device_id: str
    timestamp: int


@dataclass
class RawDocument:
    username: str
    document: str
    progress: str
    percentage: float
    device: str
    device_id: str
    timestamp: int
