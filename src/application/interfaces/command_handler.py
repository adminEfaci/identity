"""Command Handler interface for the Identity module."""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

TCommand = TypeVar('TCommand')
TResult = TypeVar('TResult')


class ICommandHandler(ABC, Generic[TCommand, TResult]):
    """Interface for command handlers in the CQRS pattern.

    Command handlers are responsible for processing commands that
    represent write operations in the system.

    Type Parameters:
        TCommand: The type of command this handler processes
        TResult: The type of result this handler returns
    """

    @abstractmethod
    async def handle(self, command: TCommand) -> TResult:
        """Handle the given command.

        Args:
            command: The command to process

        Returns:
            The result of processing the command

        Raises:
            Various domain or application exceptions based on business rules
        """
        pass
