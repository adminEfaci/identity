"""Query Handler interface for the Identity module."""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

TQuery = TypeVar('TQuery')
TResult = TypeVar('TResult')


class IQueryHandler(ABC, Generic[TQuery, TResult]):
    """Interface for query handlers in the CQRS pattern.

    Query handlers are responsible for processing queries that
    represent read operations in the system.

    Type Parameters:
        TQuery: The type of query this handler processes
        TResult: The type of result this handler returns
    """

    @abstractmethod
    async def handle(self, query: TQuery) -> TResult:
        """Handle the given query.

        Args:
            query: The query to process

        Returns:
            The result of processing the query

        Raises:
            Various domain or application exceptions based on business rules
        """
        pass
