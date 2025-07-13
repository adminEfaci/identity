"""Tests for presentation layer components.

This module contains comprehensive tests for the presentation layer including
REST API endpoints, GraphQL resolvers, middleware, and authentication.
"""

import json
from datetime import datetime
from typing import Any, Dict
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from strawberry.fastapi import GraphQLRouter

from src.application.dtos import CreateUserDto, ModifyUserDto, UserDto
from src.application.interfaces.user_service import IUserService
from src.domain.exceptions import (
    InvalidUserDataError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from src.infrastructure.config import SecurityConfig
from src.infrastructure.security import JWTTokenService
from src.presentation.app import create_app
from src.presentation.graphql.resolvers import schema
from src.presentation.middleware.auth import JWTAuthMiddleware


class TestUserService(IUserService):
    """Mock user service for testing."""
    
    def __init__(self) -> None:
        """Initialize mock user service."""
        self.users: Dict[str, UserDto] = {}
        self.next_id = 1
    
    async def create_user(self, user_data: CreateUserDto) -> UserDto:
        """Mock create user."""
        # Check for existing users
        for user in self.users.values():
            if user.email == user_data.email:
                raise UserAlreadyExistsError(f"User with email {user_data.email} already exists")
            if user.username == user_data.username:
                raise UserAlreadyExistsError(f"User with username {user_data.username} already exists")
        
        # Create new user
        user_id = str(self.next_id)
        self.next_id += 1
        
        user_dto = UserDto(
            id=user_id,
            email=user_data.email,
            username=user_data.username,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        self.users[user_id] = user_dto
        return user_dto
    
    async def get_user_by_id(self, user_id: str) -> UserDto | None:
        """Mock get user by ID."""
        return self.users.get(user_id)
    
    async def get_user_by_email(self, email: str) -> UserDto | None:
        """Mock get user by email."""
        for user in self.users.values():
            if user.email == email:
                return user
        return None
    
    async def get_user_by_username(self, username: str) -> UserDto | None:
        """Mock get user by username."""
        for user in self.users.values():
            if user.username == username:
                return user
        return None
    
    async def list_users(
        self, is_active: bool | None = None, limit: int = 50, offset: int = 0
    ) -> list[UserDto]:
        """Mock list users."""
        users = list(self.users.values())
        
        if is_active is not None:
            users = [user for user in users if user.is_active == is_active]
        
        return users[offset:offset + limit]
    
    async def modify_user(self, user_id: str, user_data: ModifyUserDto) -> UserDto:
        """Mock modify user."""
        user = self.users.get(user_id)
        if not user:
            raise UserNotFoundError(f"User not found: {user_id}")
        
        # Check for conflicts
        if user_data.email:
            for uid, u in self.users.items():
                if uid != user_id and u.email == user_data.email:
                    raise UserAlreadyExistsError(f"User with email {user_data.email} already exists")
        
        if user_data.username:
            for uid, u in self.users.items():
                if uid != user_id and u.username == user_data.username:
                    raise UserAlreadyExistsError(f"User with username {user_data.username} already exists")
        
        # Update user
        updated_user = UserDto(
            id=user.id,
            email=user_data.email or user.email,
            username=user_data.username or user.username,
            first_name=user_data.first_name or user.first_name,
            last_name=user_data.last_name or user.last_name,
            is_active=user_data.is_active if user_data.is_active is not None else user.is_active,
            created_at=user.created_at,
            updated_at=datetime.utcnow(),
        )
        
        self.users[user_id] = updated_user
        return updated_user
    
    async def delete_user(self, user_id: str) -> None:
        """Mock delete user."""
        if user_id not in self.users:
            raise UserNotFoundError(f"User not found: {user_id}")
        
        del self.users[user_id]


@pytest.fixture
def user_service() -> TestUserService:
    """Create test user service."""
    return TestUserService()


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create test security config."""
    return SecurityConfig(
        jwt_secret_key="test-secret-key",
        jwt_algorithm="HS256",
        jwt_access_token_expire_minutes=30,
        jwt_refresh_token_expire_days=7,
    )


@pytest.fixture
def token_service(security_config: SecurityConfig) -> JWTTokenService:
    """Create test token service."""
    return JWTTokenService(security_config)


@pytest.fixture
def app(user_service: TestUserService, security_config: SecurityConfig) -> FastAPI:
    """Create test FastAPI app."""
    return create_app(user_service, security_config, debug=True)


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def auth_token(token_service: JWTTokenService) -> str:
    """Create test authentication token."""
    return token_service.generate_access_token(
        user_id="test-user-id",
        email="test@example.com",
        roles=["user"],
    )


class TestRestAPI:
    """Tests for REST API endpoints."""
    
    def test_health_check(self, client: TestClient) -> None:
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy", "service": "identity-module"}
    
    def test_create_user(self, client: TestClient) -> None:
        """Test user creation endpoint."""
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User",
            "password": "testpassword123",
        }
        
        response = client.post("/api/users/", json=user_data)
        assert response.status_code == 201
        
        data = response.json()
        assert data["email"] == user_data["email"]
        assert data["username"] == user_data["username"]
        assert data["first_name"] == user_data["first_name"]
        assert data["last_name"] == user_data["last_name"]
        assert data["is_active"] is True
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data
    
    def test_create_user_duplicate_email(self, client: TestClient) -> None:
        """Test user creation with duplicate email."""
        user_data = {
            "email": "test@example.com",
            "username": "testuser1",
            "first_name": "Test",
            "last_name": "User",
            "password": "testpassword123",
        }
        
        # Create first user
        response = client.post("/api/users/", json=user_data)
        assert response.status_code == 201
        
        # Try to create second user with same email
        user_data["username"] = "testuser2"
        response = client.post("/api/users/", json=user_data)
        assert response.status_code == 409
    
    def test_get_user(self, client: TestClient) -> None:
        """Test get user endpoint."""
        # Create user first
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User",
            "password": "testpassword123",
        }
        
        create_response = client.post("/api/users/", json=user_data)
        assert create_response.status_code == 201
        user_id = create_response.json()["id"]
        
        # Get user
        response = client.get(f"/api/users/{user_id}")
        assert response.status_code == 200
        
        data = response.json()
        assert data["id"] == user_id
        assert data["email"] == user_data["email"]
    
    def test_get_user_not_found(self, client: TestClient) -> None:
        """Test get user endpoint with non-existent user."""
        response = client.get("/api/users/nonexistent")
        assert response.status_code == 404
    
    def test_list_users_without_auth(self, client: TestClient) -> None:
        """Test list users endpoint without authentication."""
        response = client.get("/api/users/")
        assert response.status_code == 401
    
    def test_list_users_with_auth(self, client: TestClient, auth_token: str) -> None:
        """Test list users endpoint with authentication."""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = client.get("/api/users/", headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "users" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
    
    def test_modify_user_without_auth(self, client: TestClient) -> None:
        """Test modify user endpoint without authentication."""
        response = client.patch("/api/users/test-id", json={"first_name": "Updated"})
        assert response.status_code == 401
    
    def test_modify_user_insufficient_permissions(self, client: TestClient, auth_token: str) -> None:
        """Test modify user endpoint with insufficient permissions."""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = client.patch("/api/users/other-user-id", json={"first_name": "Updated"}, headers=headers)
        assert response.status_code == 403
    
    def test_delete_user_without_auth(self, client: TestClient) -> None:
        """Test delete user endpoint without authentication."""
        response = client.delete("/api/users/test-id")
        assert response.status_code == 401


class TestGraphQLAPI:
    """Tests for GraphQL API."""
    
    def test_user_query(self, client: TestClient) -> None:
        """Test GraphQL user query."""
        # Create user first
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User",
            "password": "testpassword123",
        }
        
        create_response = client.post("/api/users/", json=user_data)
        assert create_response.status_code == 201
        user_id = create_response.json()["id"]
        
        # Query user via GraphQL
        query = """
        query GetUser($id: String!) {
            user(id: $id) {
                id
                email
                username
                firstName
                lastName
                isActive
            }
        }
        """
        
        response = client.post(
            "/graphql",
            json={"query": query, "variables": {"id": user_id}},
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "errors" not in data
        assert data["data"]["user"]["id"] == user_id
        assert data["data"]["user"]["email"] == user_data["email"]
    
    def test_create_user_mutation(self, client: TestClient) -> None:
        """Test GraphQL create user mutation."""
        mutation = """
        mutation CreateUser($input: CreateUserInput!) {
            createUser(input: $input) {
                success
                message
                user {
                    id
                    email
                    username
                }
            }
        }
        """
        
        variables = {
            "input": {
                "email": "test@example.com",
                "username": "testuser",
                "firstName": "Test",
                "lastName": "User",
                "password": "testpassword123",
            }
        }
        
        response = client.post(
            "/graphql",
            json={"query": mutation, "variables": variables},
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "errors" not in data
        assert data["data"]["createUser"]["success"] is True
        assert data["data"]["createUser"]["user"]["email"] == variables["input"]["email"]


class TestMiddleware:
    """Tests for middleware components."""
    
    def test_jwt_middleware_no_token(self, client: TestClient) -> None:
        """Test JWT middleware with no token."""
        response = client.get("/api/users/")
        assert response.status_code == 401
    
    def test_jwt_middleware_invalid_token(self, client: TestClient) -> None:
        """Test JWT middleware with invalid token."""
        headers = {"Authorization": "Bearer invalid-token"}
        response = client.get("/api/users/", headers=headers)
        assert response.status_code == 401
    
    def test_jwt_middleware_valid_token(self, client: TestClient, auth_token: str) -> None:
        """Test JWT middleware with valid token."""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = client.get("/api/users/", headers=headers)
        assert response.status_code == 200


class TestModels:
    """Tests for API models."""
    
    def test_create_user_request_validation(self) -> None:
        """Test create user request validation."""
        from src.presentation.models.api import CreateUserRequest
        
        # Valid data
        valid_data = {
            "email": "test@example.com",
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User",
            "password": "testpassword123",
        }
        
        request = CreateUserRequest(**valid_data)
        assert request.email == valid_data["email"]
        assert request.username == valid_data["username"]
    
    def test_create_user_request_invalid_email(self) -> None:
        """Test create user request with invalid email."""
        from pydantic import ValidationError
        from src.presentation.models.api import CreateUserRequest
        
        invalid_data = {
            "email": "invalid-email",
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User",
            "password": "testpassword123",
        }
        
        with pytest.raises(ValidationError):
            CreateUserRequest(**invalid_data)
    
    def test_user_response_model(self) -> None:
        """Test user response model."""
        from src.presentation.models.api import UserResponse
        
        data = {
            "id": "test-id",
            "email": "test@example.com",
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User",
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        
        response = UserResponse(**data)
        assert response.id == data["id"]
        assert response.email == data["email"]