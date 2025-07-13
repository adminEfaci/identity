"""Modify User Command Handler for the Identity module."""

from ..commands import ModifyUserCommand
from ..dtos import ModifyUserDto, UserDto
from ..interfaces import ICommandHandler, IUserService


class ModifyUserHandler(ICommandHandler[ModifyUserCommand, UserDto]):
    """Handler for ModifyUserCommand.

    This handler processes commands to modify existing users in the system.
    It delegates to the user service for the actual business logic.
    """

    def __init__(self, user_service: IUserService) -> None:
        """Initialize the handler with required dependencies.

        Args:
            user_service: The user service for business operations
        """
        self._user_service = user_service

    async def handle(self, command: ModifyUserCommand) -> UserDto:
        """Handle the ModifyUserCommand.

        Args:
            command: The command containing user modification data

        Returns:
            The modified user as a DTO

        Raises:
            UserNotFoundError: If the user does not exist
            UserAlreadyExistsError: If trying to change to an existing email/username
            InvalidUserDataError: If the user data is invalid
        """
        user_data = ModifyUserDto(
            email=command.email,
            username=command.username,
            first_name=command.first_name,
            last_name=command.last_name,
            is_active=command.is_active,
        )

        return await self._user_service.modify_user(command.user_id, user_data)
