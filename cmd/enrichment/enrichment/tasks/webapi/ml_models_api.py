# Standard Libraries
import asyncio
import json
import os
import re
import uuid

# 3rd Party Libraries
import aiohttp
import numpy as np
import structlog
import uvicorn
from enrichment.settings import EnrichmentSettings
from fastapi import FastAPI
from fastapi.responses import Response
from fastapi import APIRouter
from nemesiscommon.storage import StorageInterface
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary
from pydantic import BaseModel

logger = structlog.get_logger(module=__name__)

# extracted from the fit Keras tokenizer so we don't need Keras/Tensorflow as a requirement
CHAR_DICT = {
    "<UNK>": 1,
    "e": 2,
    "i": 3,
    "a": 4,
    "n": 5,
    "t": 6,
    "r": 7,
    "o": 8,
    "s": 9,
    "c": 10,
    "l": 11,
    "A": 12,
    "E": 13,
    "d": 14,
    "u": 15,
    "m": 16,
    "p": 17,
    "I": 18,
    "S": 19,
    "R": 20,
    "O": 21,
    "N": 22,
    "g": 23,
    "T": 24,
    "-": 25,
    "L": 26,
    "h": 27,
    "y": 28,
    "C": 29,
    "b": 30,
    "f": 31,
    "M": 32,
    "v": 33,
    "D": 34,
    "1": 35,
    "U": 36,
    "H": 37,
    "P": 38,
    "k": 39,
    "2": 40,
    "0": 41,
    "B": 42,
    "G": 43,
    "w": 44,
    "Y": 45,
    "K": 46,
    "3": 47,
    "9": 48,
    "F": 49,
    ".": 50,
    ",": 51,
    "4": 52,
    "8": 53,
    "V": 54,
    "5": 55,
    "7": 56,
    "6": 57,
    "W": 58,
    "j": 59,
    "x": 60,
    "z": 61,
    "J": 62,
    "q": 63,
    "Z": 64,
    "_": 65,
    "'": 66,
    ":": 67,
    "X": 68,
    "Q": 69,
    "/": 70,
    ")": 71,
    "(": 72,
    '"': 73,
    "!": 74,
    ";": 75,
    "*": 76,
    "@": 77,
    "\\": 78,
    "]": 79,
    "?": 80,
    "[": 81,
    "<": 82,
    ">": 83,
    "=": 84,
    "#": 85,
    "&": 86,
    "$": 87,
    "+": 88,
    "%": 89,
    "`": 90,
    "~": 91,
    "^": 92,
    "{": 93,
    "}": 94,
    "|": 95,
}


class UploadRequest(BaseModel):
    object_id: str


class NumpyEncoder(json.JSONEncoder):
    """Helper to JSONify numpy arrays."""

    def default(self, obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return json.JSONEncoder.default(self, obj)


class MlModelsApi(TaskInterface):
    storage: StorageInterface
    cfg: EnrichmentSettings

    def __init__(self, storage: StorageInterface, cfg: EnrichmentSettings) -> None:
        self.storage = storage
        self.cfg = cfg

    async def run(self) -> None:
        app = FastAPI(title="ML Models API")
        routes = MlModelsApiRoutes(
            self.storage,
            self.cfg.ml_chunk_size,
            self.cfg.tensorflow_uri,
            self.cfg.prob_threshold,
            self.cfg.context_words,
        )
        app.include_router(routes.router)
        server_config = uvicorn.Config(app, host="0.0.0.0", port=5000, log_level=self.cfg.log_level.lower())
        server = uvicorn.Server(server_config)
        logger.info("Starting ml_models service")
        await server.serve()


class MlModelsApiRoutes():
    """Inherits from Routable."""

    storage: StorageInterface
    ml_chunk_size: int
    tensorflow_uri: str
    prob_threshold: float
    context_words: int

    def __init__(
        self,
        storage: StorageInterface,
        ml_chunk_size: int,
        tensorflow_uri: str,
        prob_threshold: float,
        context_words: int,
    ) -> None:
        super().__init__()

        self.storage = storage
        self.ml_chunk_size = ml_chunk_size
        self.tensorflow_uri = tensorflow_uri
        self.prob_threshold = prob_threshold
        self.context_words = context_words

        # regex for 7-32 character mixed alphanumeric + special char
        self.password_regex = re.compile(r"^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[~!@#$%^&*_\-+=`|\()\{\}[\]:;\"'<>,.?\/])(?=.*\d).{7,32}$")

        self.router = APIRouter()
        self.router.add_api_route("/", self.home, methods=["GET"])
        self.router.add_api_route("/ready", self.ready, methods=["GET"])
        self.router.add_api_route("/passwords", self.root_post, methods=["POST"])

    @aio.time(Summary("process_document", "Time spent in process_document"))  # type: ignore
    async def process_document(self, file_path: str):
        """Processes a file through the NN/regex."""

        model_password_candidates = []
        regex_password_candidates = []

        await logger.adebug("Processing file", file_path=file_path)

        with open(file_path, "rb") as f:
            # chunking to handle large files
            while chunk := f.read(self.ml_chunk_size):
                # extract password candidates from the model
                model_password_candidates.extend(await self.extract_passwords_model(chunk))

                # extract password regex candidates from the model
                regex_password_candidates.extend(await self.extract_terms_regex(chunk, self.password_regex))

        result = {
            "object_id": file_path,
            "model_password_candidates": model_password_candidates,
            "regex_password_candidates": regex_password_candidates,
        }

        return result

    @aio.time(Summary("tokenize", "Time spent in tokenize"))  # type: ignore
    async def tokenize(self, word):
        """Tokenizes and pads the supplied word to the proper length."""

        if len(word) < 7 or len(word) > 32:
            return [0] * 32
        else:
            seq = [CHAR_DICT[char] if char in CHAR_DICT else 1 for char in word]
            seq.extend([0] * (32 - len(seq)))
            return seq

    async def remove_non_ascii(self, string):
        return "".join(char for char in string if ord(char) < 128)

    @aio.time(Summary("extract_passwords_model", "Time spent in extract_passwords_model"))  # type: ignore
    async def extract_passwords_model(self, document):
        """Tokenizes the input text, submits it to the served model,and returns words that might be passwords."""

        passwords = []
        url = f"{self.tensorflow_uri}v1/models/password:predict"

        try:
            # extract whitespace stripped words
            document = await self.remove_non_ascii(document.decode("ISO-8859-1"))
            words = np.array([word.strip() for word in document.split()])

            # turn the input words into sequences and pad them to 32
            tokenized_words = [await self.tokenize(word) for word in words]

            # post the tokenized words to the served model
            data = json.dumps({"inputs": tokenized_words})

            async with aiohttp.ClientSession() as session:
                status, retries = 0, 5

                async with session.post(url, data=data.encode("utf-8"), timeout=60) as resp:
                    status = resp.status
                    result = await resp.json()

                while status != 200 and retries > 0:
                    await asyncio.sleep(1)
                    retries = retries - 1
                    async with session.post(url, data=data.encode("utf-8"), timeout=60) as resp:
                        status = resp.status
                        result = await resp.json()

                pred = np.array(result["outputs"])

                # properly cast the predictions for each word
                pred = (pred > self.prob_threshold).astype("int32")

                # use the predictions as indicies for the words to return
                positive_indicies = np.where(pred == 1)

                for x in positive_indicies[0]:
                    left_context = words[:x][-self.context_words :]
                    password = words[x]
                    right_context = words[x + 1 : self.context_words + x + 1]

                    result = {"left_context": left_context, "password": password, "right_context": right_context}

                    passwords.append(result)

        except Exception as e:
            await logger.aexception(e, message="extract_passwords_model exception")

        return passwords

    @aio.time(Summary("extract_terms_regex", "Time spent in extract_terms_regex"))  # type: ignore
    async def extract_terms_regex(self, document, regex):
        """Runs the supplied compiled regex against extracted documents."""

        document = await self.remove_non_ascii(document.decode("ISO-8859-1"))
        words = np.array([word.strip() for word in document.split()])
        passwords = list()

        for x, word in enumerate(words):
            if regex.match(word):
                left_context = words[:x][-self.context_words :]
                password = words[x]
                right_context = words[x + 1 : self.context_words + x + 1]

                result = {"left_context": left_context, "password": password, "right_context": right_context}

                passwords.append(result)

        return passwords

    async def home(self):
        return {}

    async def ready(self):
        """
        Used for readiness probes.
        """
        return Response()

    @aio.time(Summary("passwords", "Time spent extracting passwords from a document."))  # type: ignore
    async def root_post(self, request: UploadRequest, length_filter: bool = False):
        try:
            file_uuid = uuid.UUID(request.object_id)
            with await self.storage.download(file_uuid) as temp_file:
                # TODO: should we make this an ENV variable
                if os.path.getsize(temp_file.name) > 104857600:
                    return {"error": "'object_id' file over 100 MB limit"}
                else:
                    results = await self.process_document(temp_file.name)
                    # return results
                    content = json.dumps(results, cls=NumpyEncoder)
                    return Response(content=content, media_type="application/json")
        except Exception as e:
            logger.exception(e, message="Error extracting passwords from document")
            return {"error": str(e)}
