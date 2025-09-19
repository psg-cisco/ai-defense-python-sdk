# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Configuration classes and enums for AI Defense model scanning.

This module provides configuration classes, authentication handlers, and status enums
used throughout the AI Defense model scanning system. It includes support for various
repository types and their authentication mechanisms.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict

class ScanStatus(str, Enum):
    """
    Enumeration of possible scan status values.

    This enum defines all possible states that a model scan can be in during its lifecycle,
    from initial creation through completion or failure.

    Attributes:
        NONE_SCAN_STATUS: Default/uninitialized scan status.
        PENDING: Scan has been created but not yet started.
        IN_PROGRESS: Scan is currently running.
        COMPLETED: Scan has finished successfully.
        FAILED: Scan encountered an error and failed.
        CANCELED: Scan was manually canceled before completion.
    """
    NONE_SCAN_STATUS = "NONE_SCAN_STATUS"
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class UrlType(str, Enum):
    """
    Enumeration of supported repository URL types.

    This enum defines the different types of model repositories that can be scanned
    by the AI Defense service. Each type may have different authentication and
    access patterns.

    Attributes:
        HUGGING_FACE: HuggingFace model hub repositories (huggingface.co)
    """
    HUGGING_FACE = "HUGGING_FACE"

URL_TYPE_TO_CONFIG_NAME: Dict[UrlType, str] = {
    UrlType.HUGGING_FACE: "huggingface"
}
"""
Mapping from URL types to their configuration names.

This dictionary maps UrlType enum values to the corresponding configuration
key names used in API requests and authentication structures.
"""

class BaseRepoAuth(ABC):
    """
    Abstract base class for repository authentication configurations.

    This abstract class defines the interface that all repository authentication
    implementations must follow. Each repository type (HuggingFace, GitHub, etc.)
    should implement this interface to provide their specific authentication format.

    The main purpose is to standardize how authentication credentials are converted
    to dictionary format for API requests.
    """

    @property
    @abstractmethod
    def to_dict(self) -> Dict[str, str]:
        """
        Convert authentication credentials to dictionary format.

        This abstract method must be implemented by subclasses to convert their
        specific authentication credentials into a dictionary format suitable
        for API requests.

        Returns:
            Dict[str, str]: Dictionary containing authentication credentials
                in the format expected by the repository's API.

        Example:
            For HuggingFace: {"access_token": "hf_token_value"}
        """
        pass

@dataclass
class HuggingfaceRepoAuth(BaseRepoAuth):
    """
    Authentication configuration for HuggingFace repositories.

    This class handles authentication credentials for accessing HuggingFace model
    repositories. It implements the BaseRepoAuth interface to provide HuggingFace-specific
    authentication in the format expected by the HuggingFace API.

    Args:
        token (str): HuggingFace access token. Can be obtained from your HuggingFace
            account settings. Should start with 'hf_' for user access tokens.

    Example:
        ```python
        # Create HuggingFace authentication
        auth = HuggingfaceRepoAuth(token="hf_your_token_here")
        
        # Use with repository configuration
        repo_config = RepoConfig(
            url="https://huggingface.co/username/model-name",
            auth=auth
        )
        ```
    """
    token: str

    @property
    def to_dict(self) -> Dict[str, str]:
        """
        Convert HuggingFace token to API-compatible dictionary format.

        Returns:
            Dict[str, str]: Dictionary with 'access_token' key containing the token.

        Example:
            ```python
            auth = HuggingfaceRepoAuth(token="hf_abc123")
            auth_dict = auth.to_dict
            # Returns: {"access_token": "hf_abc123"}
            ```
        """
        return {"access_token": self.token}

@dataclass
class RepoConfig:
    """
    Configuration for repository scanning operations.

    This class encapsulates all the information needed to scan a model repository,
    including the repository URL and authentication credentials. It automatically
    determines the repository type based on the URL and formats authentication
    appropriately.

    Args:
        url (str): The repository URL to scan. Must be a valid repository URL
            from a supported platform (currently HuggingFace).
        auth (Optional[BaseRepoAuth]): Authentication configuration for accessing
            the repository. If None, the repository will be accessed without
            authentication (public repositories only).

    Attributes:
        url (str): The repository URL.
        auth (Optional[BaseRepoAuth]): Authentication configuration.

    Example:
        ```python
        from aidefense.modelscan import RepoConfig, HuggingfaceRepoAuth
        
        # Public repository (no authentication)
        public_config = RepoConfig(
            url="https://huggingface.co/username/public-model"
        )
        
        # Private repository with authentication
        private_config = RepoConfig(
            url="https://huggingface.co/username/private-model",
            auth=HuggingfaceRepoAuth(token="hf_your_token")
        )
        
        # Use with ModelScanClient
        client = ModelScanClient(api_key="your_api_key")
        result = client.scan_repo(private_config)
        ```
    """
    url: str
    auth: Optional[BaseRepoAuth] = None

    @property
    def url_type(self):
        """
        Automatically determine the repository type based on the URL.

        Returns:
            UrlType: The detected repository type enum value.

        Raises:
            ValueError: If the URL doesn't match any supported repository type.

        Example:
            ```python
            config = RepoConfig(url="https://huggingface.co/user/model")
            print(config.url_type)  # UrlType.HUGGING_FACE
            ```
        """
        if "huggingface.co" in self.url:
            return UrlType.HUGGING_FACE

        raise ValueError(f"Unknown url type for url: {self.url}")

    @property
    def config(self) -> Dict[str, Dict[str, str]]:
        """
        Generate authentication configuration dictionary for API requests.

        This property converts the authentication configuration into the format
        expected by the AI Defense API, organized by repository type.

        Returns:
            Dict[str, Dict[str, str]]: Authentication configuration dictionary.
                Empty if no authentication is provided. Otherwise contains
                repository-type-specific authentication data.

        Example:
            ```python
            # With authentication
            config = RepoConfig(
                url="https://huggingface.co/user/model",
                auth=HuggingfaceRepoAuth(token="hf_token")
            )
            print(config.config)
            # Returns: {"huggingface": {"access_token": "hf_token"}}
            
            # Without authentication
            config = RepoConfig(url="https://huggingface.co/user/model")
            print(config.config)
            # Returns: {}
            ```
        """
        if not self.auth:
            return {}

        return {
            URL_TYPE_TO_CONFIG_NAME[self.url_type]: self.auth.to_dict
        }
