# # Standard Libraries
# import structlog

# # 3rd Party Libraries
# import pytest
# from enrichment.app import NemesisDb
# from enrichment.lib.nemesis_db import FileInfo
# from enrichment.tasks.raw_data_tag_service.seatbelt_datatypes import (
#     RegistryValueKindEnum,
#     SeatbeltBaseDTO,
#     SeatbeltDtoTypes,
#     SeatbeltFileInfo,
#     SeatbeltRegistryValue,
# )
# from nemesiscommon.messaging import MessageQueueProducerInterface
# from nemesispb.nemesis_pb2 import Metadata, RegistryValueIngestion


# @pytest.fixture
# def raw_data_processor(logger: logging.Logger, nemesis_db: NemesisDb, message_producer: MessageQueueProducerInterface) -> RawDataProcessor:
#     return RawDataProcessor(logger, nemesis_db, message_producer)


# @pytest.mark.asyncio
# class TestRawDataTagService:
#     count = 0

#     async def test_read_seatbelt_json_file(self, mock_file_open, raw_data_processor: RawDataProcessor) -> None:
#         mock_file_open.read_data = """{"Type":"asdf1","Data":{"Key":"key1"}}
# {"Type":"asdf2","Data":{"Key":"key2"}}
# """

#         metadata = Metadata()
#         self.count = 0

#         async def count_entries(dto: SeatbeltBaseDTO, metadata: Metadata) -> None:
#             self.count += 1

#         await raw_data_processor.read_seatbelt_json_file("seatbelt.json", metadata, count_entries)
#         assert self.count == 2

#     async def test_process_seatbelt_dto(self, raw_data_processor: RawDataProcessor):
#         metadata = Metadata()
#         dto = SeatbeltBaseDTO(SeatbeltDtoTypes.REGISTRY_VALUE.value, {"Key": "key1"})

#         await raw_data_processor.process_seatbelt_dto(dto, metadata)
#         assert raw_data_processor.reg_value_q.message_count == 1

#     async def test_convert_reg_dto_to_pb(self, raw_data_processor: RawDataProcessor):
#         key = r"HKLM\Software"
#         value_name = "valueName"
#         value = "value"
#         value_kind = RegistryValueKindEnum.SZ
#         sddl = None
#         data = SeatbeltRegistryValue(key, value_name, value, value_kind, sddl)

#         out = await raw_data_processor.convert_reg_dto_to_pb(data, Metadata())

#         assert out.data[0].key == key
#         assert out.data[0].value_name == value_name
#         assert out.data[0].value == value
#         assert out.data[0].value_kind == value_kind.value
#         assert out.data[0].HasField("sddl") is False

#     async def test_convert_reg_dto_to_pb_null_values(self, raw_data_processor: RawDataProcessor):
#         data = SeatbeltRegistryValue("key", "valueName", "value", None, None)
#         out = await raw_data_processor.convert_reg_dto_to_pb(data, Metadata())
#         data = out.data[0]
#         data.ClearField("value")

#         with pytest.raises(ValueError):
#             # Should fail since "key" should always be present, so you can't check if it's NOT present
#             assert data.HasField("key")

#         assert data.HasField("value_name") is True
#         assert data.HasField("value") is False
#         assert data.HasField("value_kind") is False
#         assert data.HasField("sddl") is False

#     async def test_convert_fileinfo_dto_to_fileinfo(self, raw_data_processor: RawDataProcessor):
#         data = SeatbeltFileInfo()

#         out = await raw_data_processor.convert_fileinfo_dto_to_fileinfo(data, Metadata())
#         # data = out.data[0]
#         # data.ClearField("path")

#         # with pytest.raises(ValueError):
#         #     # Should fail since "path" should always be present, so you can't check if it's NOT present
#         #     assert data.HasField("path")

#         # assert data.HasField("name") is True
#         # assert data.HasField("extension") is True
#         # assert data.HasField("size") is True
#         # assert data.HasField("created") is True
#         # assert data.HasField("modified") is True
#         # assert data.HasField("accessed") is True
