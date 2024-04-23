# Standard Libraries
import json
from typing import Dict, List, Optional

# 3rd Party Libraries
from enrichment.tasks.webapi.crack_list.dictionary import Dictionary, default_dictionary

# TODO: make these ENV variables
MIN_LENGTH = 3
MAX_LENGTH = 30


class Wordlist:
    def __init__(
        self,
        dictionary: Dictionary = default_dictionary,
        raw_wordlist: Optional[Dict[str, int]] = None,
    ):
        self.dictionary = dictionary
        if raw_wordlist is None:
            self.wordlist = {}
        else:
            self.wordlist = raw_wordlist

    @staticmethod
    def from_json(json_str: str, dictionary: Dictionary = default_dictionary) -> "Wordlist":
        """
        Create a Wordlist from a JSON string
        """
        try:
            raw_wordlist = json.loads(json_str)
            return Wordlist(dictionary=dictionary, raw_wordlist=raw_wordlist)
        except Exception:
            return None

    def _tokenize(self, text: str) -> List[str]:
        return text.split()

    def _length_filter(self, words: List[str]) -> List[str]:
        """
        Filter out words that are too short or too long
        """
        return [word for word in words if MIN_LENGTH <= len(word) <= MAX_LENGTH]

    def to_json(self) -> str:
        """
        Return a JSON string representation of the wordlist
        """
        return json.dumps(self.wordlist)

    def add(self, text: str, len_filter: bool = False) -> None:
        """
        Add a string to the wordlist. Only performs a dictionary filter for new
        input. Does not recompute the filtered words for the entire wordlist.

        :param text: The string to add
        """
        tokens = self._tokenize(text)
        if len_filter:
            tokens = self._length_filter(tokens)
        tokens = self.dictionary.filter(tokens)
        for token in tokens:
            self.wordlist[token] = self.wordlist.get(token, 0) + 1

    def get(self, count: Optional[int] = None) -> List[str]:
        """
        Return a list of the most common words in the wordlist

        :param count: The number of words to return. If None, return all words.
        """
        xs = sorted(self.wordlist, key=self.wordlist.__getitem__, reverse=True)
        if count is not None:
            return xs[:count]
        return xs
