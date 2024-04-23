import logging

logger = logging.getLogger(__name__)



class Database:
    pass
    # def __init__(self, db_url: str) -> None:
    #     self._engine = create_async_engine(db_url, echo=False)

    #     self.session_factory = async_sessionmaker(
    #             autocommit=False,
    #             autoflush=False,
    #             bind=self._engine,
    #         )


    # def create_database(self) -> None:
    #     Base.metadata.create_all(self._engine)

    # @contextmanager
    # def session(self):
    #     session: Session = self._session_factory()
    #     try:
    #         yield session
    #     except Exception:
    #         logger.exception("Session rollback because of exception")
    #         session.rollback()
    #         raise
    #     finally:
    #         session.close()