# Standard Libraries
from typing import List, Optional, Set


class Dictionary:
    def __init__(self, dictionary_path: Optional[str] = None, words: Optional[Set[str]] = None):
        if dictionary_path is None and words is None:
            raise ValueError("No dictionary path or words provided")

        self.words = words or set()

        if dictionary_path:
            with open(dictionary_path, "r") as f:
                for line in f:
                    self.words.add(line.strip())

        if words:
            self.words = words

    def filter(self, tokens: List[str]) -> List[str]:
        return [token for token in tokens if token not in self.words]


# use the `wamerican` ~100k word dictionary to filter out
default_dictionary = Dictionary("/usr/share/dict/words")
