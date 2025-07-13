"""Create User Command Handler for the Identity module."""

from ..commands import CreateUserCommand
from ..dtos import CreateUserDto, UserDto
from ..interfaces import ICommandHandler, IUserService


class CreateUserHandler(ICommandHandler[CreateUserCommand, UserDto]):
    """Handler for CreateUserCommand.

    This handler processes commands to create new users in the system.
    It delegates to the user service for the actual business logic.
    """

    def __init__(self, user_service: IUserService) -> None:
        """Initialize the handler with required dependencies.

        Args:
            user_service: The user service for business operations
        """
        self._user_service = user_service

    async def handle(self, command: CreateUserCommand) -> UserDto:
        """Handle the CreateUserCommand.

        Args:
            command: The command containing user creation data

        Returns:
            The created user as a DTO

        Raises:
            UserAlreadyExistsError: If a user with the same email or username exists
            InvalidUserDataError: If the user data is invalid
        """
        user_data = CreateUserDto(
            email=command.email,
            username=command.username,
            first_name=command.first_name,
            last_name=command.last_name,
            password=command.password
        )

        return await self._user_service.create_user(user_data)
