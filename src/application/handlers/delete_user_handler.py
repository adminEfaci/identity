"""Delete User Command Handler for the Identity module."""

from ..commands import DeleteUserCommand
from ..interfaces import ICommandHandler, IUserService


class DeleteUserHandler(ICommandHandler[DeleteUserCommand, None]):
    """Handler for DeleteUserCommand.

    This handler processes commands to delete users from the system.
    It delegates to the user service for the actual business logic.
    """

    def __init__(self, user_service: IUserService) -> None:
        """Initialize the handler with required dependencies.

        Args:
            user_service: The user service for business operations
        """
        self._user_service = user_service

    async def handle(self, command: DeleteUserCommand) -> None:
        """Handle the DeleteUserCommand.

        Args:
            command: The command containing user deletion data

        Raises:
            UserNotFoundError: If the user does not exist
        """
        await self._user_service.delete_user(command.user_id)
