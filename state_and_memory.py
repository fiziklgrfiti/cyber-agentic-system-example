#!/usr/bin/env python3
"""
Security Capability Measurement Program - Phase 1 Implementation
Milestone 3: Core Agent Framework - State and Memory

This module implements memory management components, state persistence,
and conversation history tracking for the agent framework.
"""

import os
import sys
import time
import json
import uuid
import pickle
import logging
import datetime
from typing import Dict, List, Any, Tuple, Optional, Union, Set, TypeVar, Generic
from collections import deque, defaultdict
from contextlib import contextmanager
from pathlib import Path

# Try to import components from previous milestones
try:
    from environmental import ( # milestone 1
        MessageType, MessageContent, AgentMessage, AgentConfig,
        logger, DEFAULT_MODEL, DEFAULT_TEMPERATURE
    )
    from base_structure import BaseAgent, MessageBus # milestone 2
except ImportError:
    # For standalone testing
    from enum import Enum
    from pydantic import BaseModel, Field
    
    # Minimal versions for standalone testing
    class MessageType(str, Enum):
        QUERY = "query"
        RESPONSE = "response"
        REQUEST = "request"
        NOTIFICATION = "notification"
        ERROR = "error"
        RESULT = "result"
        COMMAND = "command"
        STATUS = "status"
    
    class MessageContent(BaseModel):
        type: MessageType
        content: Any
        metadata: Dict[str, Any] = Field(default_factory=dict)
        timestamp: float = Field(default_factory=time.time)
    
    class AgentMessage(BaseModel):
        id: str = Field(default_factory=lambda: str(uuid.uuid4()))
        sender: str
        receiver: Optional[str] = None
        broadcast: bool = False
        content: MessageContent
        created_at: str = Field(default_factory=lambda: datetime.datetime.now().isoformat())
        thread_id: Optional[str] = None
        reply_to: Optional[str] = None

        def dict(self):
            return self.model_dump()
    
    class BaseAgent:
        """Stub for BaseAgent for standalone testing."""
        def __init__(self, agent_id, agent_type, description, message_bus):
            self.agent_id = agent_id
            self.agent_type = agent_type
            self.description = description
            self.message_bus = message_bus
    
    class MessageBus:
        """Stub for MessageBus for standalone testing."""
        def __init__(self):
            pass

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('security_measurement.log')
        ]
    )
    logger = logging.getLogger('security_measurement')

    # Constants
    DEFAULT_MODEL = "llama3.2:latest"
    DEFAULT_TEMPERATURE = 0.1

# Create data directories
os.makedirs("data/state", exist_ok=True)
os.makedirs("data/memory", exist_ok=True)
os.makedirs("data/conversations", exist_ok=True)


# Type variable for generic types
T = TypeVar('T')


class MemoryInterface(Generic[T]):
    """
    Abstract interface for memory implementations.
    Defines the basic operations that all memory types must support.
    """
    
    def store(self, key: str, value: T) -> bool:
        """
        Store a value in memory.
        
        Args:
            key: Key to store under
            value: Value to store
            
        Returns:
            Boolean indicating success
        """
        raise NotImplementedError
    
    def retrieve(self, key: str, default: Optional[T] = None) -> Optional[T]:
        """
        Retrieve a value from memory.
        
        Args:
            key: Key to retrieve
            default: Default value if key not found
            
        Returns:
            Stored value or default
        """
        raise NotImplementedError
    
    def delete(self, key: str) -> bool:
        """
        Delete a value from memory.
        
        Args:
            key: Key to delete
            
        Returns:
            Boolean indicating success
        """
        raise NotImplementedError
    
    def contains(self, key: str) -> bool:
        """
        Check if memory contains a key.
        
        Args:
            key: Key to check
            
        Returns:
            Boolean indicating if key exists
        """
        raise NotImplementedError
    
    def clear(self) -> bool:
        """
        Clear all values from memory.
        
        Returns:
            Boolean indicating success
        """
        raise NotImplementedError
    
    def get_all_keys(self) -> List[str]:
        """
        Get all keys in memory.
        
        Returns:
            List of keys
        """
        raise NotImplementedError


class InMemoryStore(MemoryInterface[T]):
    """
    Simple in-memory implementation of the memory interface.
    """
    
    def __init__(self):
        """Initialize the in-memory store."""
        self._store = {}  # Rename to avoid name collision with method
        logger.debug("InMemoryStore initialized")
    
    def store(self, key: str, value: T) -> bool:
        """Store a value in memory."""
        self._store[key] = value
        return True
    
    def retrieve(self, key: str, default: Optional[T] = None) -> Optional[T]:
        """Retrieve a value from memory."""
        if key in self._store:
            return self._store[key]
        return default
    
    def delete(self, key: str) -> bool:
        """Delete a value from memory."""
        if key in self._store:
            del self._store[key]
            return True
        return False
    
    def contains(self, key: str) -> bool:
        """Check if memory contains a key."""
        return key in self._store
    
    def clear(self) -> bool:
        """Clear all values from memory."""
        self._store.clear()
        return True
    
    def get_all_keys(self) -> List[str]:
        """Get all keys in memory."""
        return list(self._store.keys())


class PersistentStore(MemoryInterface[T]):
    """
    Persistent implementation of the memory interface using files for storage.
    """
    
    def __init__(self, directory: str, extension: str = ".pkl"):
        """
        Initialize the persistent store.
        
        Args:
            directory: Directory to store files in
            extension: File extension to use
        """
        self.directory = Path(directory)
        self.extension = extension
        
        # Create directory if it doesn't exist
        os.makedirs(self.directory, exist_ok=True)
        
        # In-memory cache for faster access
        self.cache = {}
        self.cache_enabled = True
        
        logger.debug(f"PersistentStore initialized in directory: {directory}")
    
    def _get_path(self, key: str) -> Path:
        """
        Get the file path for a key.
        
        Args:
            key: Key to get path for
            
        Returns:
            Path object
        """
        # Sanitize key for filename
        safe_key = "".join(c if c.isalnum() or c in "._- " else "_" for c in key)
        return self.directory / f"{safe_key}{self.extension}"
    
    def store(self, key: str, value: T) -> bool:
        """Store a value persistently."""
        try:
            path = self._get_path(key)
            
            with open(path, 'wb') as f:
                pickle.dump(value, f)
            
            # Update cache
            if self.cache_enabled:
                self.cache[key] = value
            
            return True
        except Exception as e:
            logger.error(f"Error storing value for key {key}: {str(e)}")
            return False
    
    def retrieve(self, key: str, default: Optional[T] = None) -> Optional[T]:
        """Retrieve a value from persistent storage."""
        # Check cache first
        if self.cache_enabled and key in self.cache:
            return self.cache[key]
        
        path = self._get_path(key)
        
        if not path.exists():
            return default
        
        try:
            with open(path, 'rb') as f:
                value = pickle.load(f)
            
            # Update cache
            if self.cache_enabled:
                self.cache[key] = value
            
            return value
        except Exception as e:
            logger.error(f"Error retrieving value for key {key}: {str(e)}")
            return default
    
    def delete(self, key: str) -> bool:
        """Delete a value from persistent storage."""
        path = self._get_path(key)
        
        if not path.exists():
            return False
        
        try:
            path.unlink()
            
            # Remove from cache
            if self.cache_enabled and key in self.cache:
                del self.cache[key]
            
            return True
        except Exception as e:
            logger.error(f"Error deleting key {key}: {str(e)}")
            return False
    
    def contains(self, key: str) -> bool:
        """Check if persistent storage contains a key."""
        # Check cache first
        if self.cache_enabled and key in self.cache:
            return True
        
        return self._get_path(key).exists()
    
    def clear(self) -> bool:
        """Clear all values from persistent storage."""
        try:
            for path in self.directory.glob(f"*{self.extension}"):
                path.unlink()
            
            # Clear cache
            if self.cache_enabled:
                self.cache.clear()
            
            return True
        except Exception as e:
            logger.error(f"Error clearing persistent store: {str(e)}")
            return False
    
    def get_all_keys(self) -> List[str]:
        """Get all keys in persistent storage."""
        try:
            keys = []
            ext_len = len(self.extension)
            
            for path in self.directory.glob(f"*{self.extension}"):
                keys.append(path.name[:-ext_len])
            
            return keys
        except Exception as e:
            logger.error(f"Error getting keys from persistent store: {str(e)}")
            return []
    
    def disable_cache(self):
        """Disable the in-memory cache."""
        self.cache_enabled = False
        self.cache.clear()
    
    def enable_cache(self):
        """Enable the in-memory cache."""
        self.cache_enabled = True


class JsonStore(MemoryInterface[Any]):
    """
    JSON implementation of the memory interface using files for storage.
    Useful for storing configurations and other JSON-serializable data.
    """
    
    def __init__(self, directory: str, extension: str = ".json"):
        """
        Initialize the JSON store.
        
        Args:
            directory: Directory to store files in
            extension: File extension to use
        """
        self.directory = Path(directory)
        self.extension = extension
        
        # Create directory if it doesn't exist
        os.makedirs(self.directory, exist_ok=True)
        
        # In-memory cache for faster access
        self.cache = {}
        self.cache_enabled = True
        
        logger.debug(f"JsonStore initialized in directory: {directory}")
    
    def _get_path(self, key: str) -> Path:
        """
        Get the file path for a key.
        
        Args:
            key: Key to get path for
            
        Returns:
            Path object
        """
        # Sanitize key for filename
        safe_key = "".join(c if c.isalnum() or c in "._- " else "_" for c in key)
        return self.directory / f"{safe_key}{self.extension}"
    
    def store(self, key: str, value: Any) -> bool:
        """Store a value as JSON."""
        try:
            path = self._get_path(key)
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(value, f, indent=2, default=str)
            
            # Update cache
            if self.cache_enabled:
                self.cache[key] = value
            
            return True
        except Exception as e:
            logger.error(f"Error storing JSON for key {key}: {str(e)}")
            return False
    
    def retrieve(self, key: str, default: Any = None) -> Any:
        """Retrieve a value from JSON storage."""
        # Check cache first
        if self.cache_enabled and key in self.cache:
            return self.cache[key]
        
        path = self._get_path(key)
        
        if not path.exists():
            return default
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                value = json.load(f)
            
            # Update cache
            if self.cache_enabled:
                self.cache[key] = value
            
            return value
        except Exception as e:
            logger.error(f"Error retrieving JSON for key {key}: {str(e)}")
            return default
    
    def delete(self, key: str) -> bool:
        """Delete a value from JSON storage."""
        path = self._get_path(key)
        
        if not path.exists():
            return False
        
        try:
            path.unlink()
            
            # Remove from cache
            if self.cache_enabled and key in self.cache:
                del self.cache[key]
            
            return True
        except Exception as e:
            logger.error(f"Error deleting JSON for key {key}: {str(e)}")
            return False
    
    def contains(self, key: str) -> bool:
        """Check if JSON storage contains a key."""
        # Check cache first
        if self.cache_enabled and key in self.cache:
            return True
        
        return self._get_path(key).exists()
    
    def clear(self) -> bool:
        """Clear all values from JSON storage."""
        try:
            for path in self.directory.glob(f"*{self.extension}"):
                path.unlink()
            
            # Clear cache
            if self.cache_enabled:
                self.cache.clear()
            
            return True
        except Exception as e:
            logger.error(f"Error clearing JSON store: {str(e)}")
            return False
    
    def get_all_keys(self) -> List[str]:
        """Get all keys in JSON storage."""
        try:
            keys = []
            ext_len = len(self.extension)
            
            for path in self.directory.glob(f"*{self.extension}"):
                keys.append(path.name[:-ext_len])
            
            return keys
        except Exception as e:
            logger.error(f"Error getting keys from JSON store: {str(e)}")
            return []


class AgentMemory:
    """
    Memory system for agents that provides different types of storage.
    Includes short-term memory (in-memory), long-term memory (persistent),
    and conversation history.
    """
    
    def __init__(self, agent_id: str, memory_root: str = "data"):
        """
        Initialize agent memory.
        
        Args:
            agent_id: ID of the agent owning this memory
            memory_root: Root directory for persistent storage
        """
        self.agent_id = agent_id
        
        # Set up memory paths
        memory_path = Path(memory_root) / "memory" / agent_id
        state_path = Path(memory_root) / "state" / agent_id
        conversations_path = Path(memory_root) / "conversations" / agent_id
        
        # Create memory stores
        self.short_term = InMemoryStore()
        self.long_term = PersistentStore(memory_path)
        self.state = JsonStore(state_path)
        self.conversations = JsonStore(conversations_path)
        
        # Conversation management
        self.active_conversations = set()
        self.default_conversation = f"{agent_id}_default"
        
        logger.info(f"AgentMemory initialized for agent {agent_id}")
    
    def save_state(self, state_data: Dict[str, Any]) -> bool:
        """
        Save agent state.
        
        Args:
            state_data: State data to save
            
        Returns:
            Boolean indicating success
        """
        # Add timestamp
        state_data["_last_updated"] = datetime.datetime.now().isoformat()
        
        return self.state.store("current_state", state_data)
    
    def load_state(self) -> Dict[str, Any]:
        """
        Load agent state.
        
        Returns:
            Agent state data
        """
        return self.state.retrieve("current_state", {})
    
    def remember(self, key: str, value: Any) -> bool:
        """
        Store a value in short-term memory.
        
        Args:
            key: Key to store under
            value: Value to store
            
        Returns:
            Boolean indicating success
        """
        return self.short_term.store(key, value)
    
    def recall(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value from short-term memory.
        
        Args:
            key: Key to retrieve
            default: Default value if key not found
            
        Returns:
            Stored value or default
        """
        return self.short_term.retrieve(key, default)
    
    def memorize(self, key: str, value: Any) -> bool:
        """
        Store a value in long-term memory.
        
        Args:
            key: Key to store under
            value: Value to store
            
        Returns:
            Boolean indicating success
        """
        # Store in both short-term and long-term memory
        self.short_term.store(key, value)
        return self.long_term.store(key, value)
    
    def recollect(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value from memory, checking short-term first, then long-term.
        
        Args:
            key: Key to retrieve
            default: Default value if key not found
            
        Returns:
            Stored value or default
        """
        # Check short-term memory first
        if self.short_term.contains(key):
            return self.short_term.retrieve(key)
        
        # Check long-term memory
        value = self.long_term.retrieve(key, default)
        
        # Cache in short-term memory if found
        if value != default:
            self.short_term.store(key, value)
        
        return value
    
    def forget(self, key: str) -> bool:
        """
        Delete a value from all memory types.
        
        Args:
            key: Key to delete
            
        Returns:
            Boolean indicating success
        """
        short_term_success = self.short_term.delete(key)
        long_term_success = self.long_term.delete(key)
        
        return short_term_success or long_term_success
    
    def create_conversation(self, conversation_id: str = None) -> str:
        """
        Create a new conversation.
        
        Args:
            conversation_id: Optional ID for the conversation
            
        Returns:
            ID of the created conversation
        """
        if conversation_id is None:
            conversation_id = f"{self.agent_id}_{int(time.time())}"
        
        # Initialize empty conversation
        conversation = {
            "id": conversation_id,
            "created_at": datetime.datetime.now().isoformat(),
            "updated_at": datetime.datetime.now().isoformat(),
            "messages": []
        }
        
        self.conversations.store(conversation_id, conversation)
        self.active_conversations.add(conversation_id)
        
        return conversation_id
    
    def add_message_to_conversation(self, message: AgentMessage, conversation_id: str = None) -> bool:
        """
        Add a message to a conversation.
        
        Args:
            message: Message to add
            conversation_id: ID of the conversation
            
        Returns:
            Boolean indicating success
        """
        # Use default conversation if none specified
        if conversation_id is None:
            conversation_id = self.default_conversation
            
            # Create default conversation if it doesn't exist
            if not self.conversations.contains(conversation_id):
                self.create_conversation(conversation_id)
        
        # Get conversation
        conversation = self.conversations.retrieve(conversation_id)
        
        if conversation is None:
            logger.warning(f"Conversation {conversation_id} not found")
            return False
        
        # Add message to conversation
        conversation["messages"].append(message.model_dump() if hasattr(message, "model_dump") else message.__dict__)
        conversation["updated_at"] = datetime.datetime.now().isoformat()
        
        # Update conversation
        return self.conversations.store(conversation_id, conversation)
    
    def get_conversation(self, conversation_id: str = None) -> Dict[str, Any]:
        """
        Get a conversation.
        
        Args:
            conversation_id: ID of the conversation
            
        Returns:
            Conversation data
        """
        # Use default conversation if none specified
        if conversation_id is None:
            conversation_id = self.default_conversation
        
        return self.conversations.retrieve(conversation_id)
    
    def get_conversation_messages(self, conversation_id: str = None) -> List[Dict[str, Any]]:
        """
        Get messages from a conversation.
        
        Args:
            conversation_id: ID of the conversation
            
        Returns:
            List of messages
        """
        conversation = self.get_conversation(conversation_id)
        
        if conversation is None:
            return []
        
        return conversation.get("messages", [])
    
    def close_conversation(self, conversation_id: str) -> bool:
        """
        Close a conversation.
        
        Args:
            conversation_id: ID of the conversation
            
        Returns:
            Boolean indicating success
        """
        if conversation_id in self.active_conversations:
            self.active_conversations.remove(conversation_id)
        
        return True
    
    def clear_short_term_memory(self) -> bool:
        """
        Clear short-term memory.
        
        Returns:
            Boolean indicating success
        """
        return self.short_term.clear()


class ConversationHistory:
    """
    Manages conversation history across agents in the system.
    Provides utilities for retrieving, searching, and analyzing conversations.
    """
    
    def __init__(self, storage_path: str = "data/conversations"):
        """
        Initialize conversation history.
        
        Args:
            storage_path: Path for conversation storage
        """
        self.storage_path = Path(storage_path)
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Create agent-specific directories
        self.agent_stores = {}
        
        logger.info(f"ConversationHistory initialized in {storage_path}")
    
    def _get_agent_store(self, agent_id: str) -> JsonStore:
        """
        Get or create a store for an agent.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            JsonStore for the agent
        """
        if agent_id not in self.agent_stores:
            agent_path = self.storage_path / agent_id
            self.agent_stores[agent_id] = JsonStore(agent_path)
        
        return self.agent_stores[agent_id]
    
    def store_conversation(self, agent_id: str, conversation_id: str, conversation: Dict[str, Any]) -> bool:
        """
        Store a conversation.
        
        Args:
            agent_id: ID of the agent
            conversation_id: ID of the conversation
            conversation: Conversation data
            
        Returns:
            Boolean indicating success
        """
        store = self._get_agent_store(agent_id)
        return store.store(conversation_id, conversation)
    
    def retrieve_conversation(self, agent_id: str, conversation_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a conversation.
        
        Args:
            agent_id: ID of the agent
            conversation_id: ID of the conversation
            
        Returns:
            Conversation data or None if not found
        """
        store = self._get_agent_store(agent_id)
        return store.retrieve(conversation_id)
    
    def get_agent_conversations(self, agent_id: str) -> List[str]:
        """
        Get all conversation IDs for an agent.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            List of conversation IDs
        """
        store = self._get_agent_store(agent_id)
        return store.get_all_keys()
    
    def search_conversations(self, agent_id: str, search_term: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Search conversations for an agent.
        
        Args:
            agent_id: ID of the agent
            search_term: Term to search for
            
        Returns:
            Dictionary mapping conversation IDs to lists of matching messages
        """
        store = self._get_agent_store(agent_id)
        results = {}
        
        for conversation_id in store.get_all_keys():
            conversation = store.retrieve(conversation_id)
            
            if conversation is None:
                continue
            
            matching_messages = []
            
            for message in conversation.get("messages", []):
                content = message.get("content", {}).get("content", "")
                
                if isinstance(content, str) and search_term.lower() in content.lower():
                    matching_messages.append(message)
            
            if matching_messages:
                results[conversation_id] = matching_messages
        
        return results
    
    def export_conversation(self, agent_id: str, conversation_id: str, format: str = "json") -> Optional[str]:
        """
        Export a conversation to a specific format.
        
        Args:
            agent_id: ID of the agent
            conversation_id: ID of the conversation
            format: Format to export to (json, text, markdown)
            
        Returns:
            Exported conversation or None if not found
        """
        conversation = self.retrieve_conversation(agent_id, conversation_id)
        
        if conversation is None:
            return None
        
        if format == "json":
            return json.dumps(conversation, indent=2, default=str)
        
        elif format == "text":
            output = f"Conversation: {conversation_id}\n"
            output += f"Created: {conversation.get('created_at', 'Unknown')}\n\n"
            
            for message in conversation.get("messages", []):
                sender = message.get("sender", "Unknown")
                content = message.get("content", {}).get("content", "")
                timestamp = message.get("created_at", "Unknown")
                
                output += f"[{timestamp}] {sender}: {content}\n\n"
            
            return output
        
        elif format == "markdown":
            output = f"# Conversation: {conversation_id}\n\n"
            output += f"*Created: {conversation.get('created_at', 'Unknown')}*\n\n"
            
            for message in conversation.get("messages", []):
                sender = message.get("sender", "Unknown")
                content = message.get("content", {}).get("content", "")
                timestamp = message.get("created_at", "Unknown")
                
                output += f"**{sender}** *({timestamp})*\n\n{content}\n\n---\n\n"
            
            return output
        
        else:
            logger.warning(f"Unsupported export format: {format}")
            return None


class StateManager:
    """
    Manages state for all agents in the system.
    Provides persistence, versioning, and recovery capabilities.
    """
    
    def __init__(self, storage_path: str = "data/state"):
        """
        Initialize state manager.
        
        Args:
            storage_path: Path for state storage
        """
        self.storage_path = Path(storage_path)
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Create agent-specific directories
        self.agent_stores = {}
        
        # Version tracking
        self.state_versions = defaultdict(int)
        
        logger.info(f"StateManager initialized in {storage_path}")
    
    def _get_agent_store(self, agent_id: str) -> JsonStore:
        """
        Get or create a store for an agent.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            JsonStore for the agent
        """
        if agent_id not in self.agent_stores:
            agent_path = self.storage_path / agent_id
            self.agent_stores[agent_id] = JsonStore(agent_path)
        
        return self.agent_stores[agent_id]
    
    def save_state(self, agent_id: str, state: Dict[str, Any], checkpoint: bool = False) -> bool:
        """
        Save state for an agent.
        
        Args:
            agent_id: ID of the agent
            state: State data
            checkpoint: Whether to create a versioned checkpoint
            
        Returns:
            Boolean indicating success
        """
        store = self._get_agent_store(agent_id)
        
        # Add metadata
        state["_last_updated"] = datetime.datetime.now().isoformat()
        
        # Save current state
        success = store.store("current", state)
        
        # Create checkpoint if requested
        if checkpoint and success:
            version = self.state_versions[agent_id] + 1
            self.state_versions[agent_id] = version
            
            checkpoint_id = f"v{version}"
            state["_version"] = version
            
            store.store(checkpoint_id, state)
            logger.debug(f"Created state checkpoint {checkpoint_id} for agent {agent_id}")
        
        return success
    
    def load_state(self, agent_id: str, version: str = "current") -> Optional[Dict[str, Any]]:
        """
        Load state for an agent.
        
        Args:
            agent_id: ID of the agent
            version: Version to load (current or checkpoint ID)
            
        Returns:
            State data or None if not found
        """
        store = self._get_agent_store(agent_id)
        return store.retrieve(version)
    
    def list_checkpoints(self, agent_id: str) -> List[str]:
        """
        List all checkpoints for an agent.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            List of checkpoint IDs
        """
        store = self._get_agent_store(agent_id)
        
        # Filter out 'current' and return only version checkpoints
        return [key for key in store.get_all_keys() if key != "current"]
    
    def revert_to_checkpoint(self, agent_id: str, checkpoint_id: str) -> bool:
        """
        Revert to a checkpoint.
        
        Args:
            agent_id: ID of the agent
            checkpoint_id: ID of the checkpoint
            
        Returns:
            Boolean indicating success
        """
        store = self._get_agent_store(agent_id)
        
        # Get checkpoint state
        checkpoint_state = store.retrieve(checkpoint_id)
        
        if checkpoint_state is None:
            logger.warning(f"Checkpoint {checkpoint_id} not found for agent {agent_id}")
            return False
        
        # Update current state with checkpoint
        checkpoint_state["_reverted_from"] = checkpoint_id
        checkpoint_state["_revert_time"] = datetime.datetime.now().isoformat()
        
        return store.store("current", checkpoint_state)
    
    def clean_old_checkpoints(self, agent_id: str, keep_count: int = 5) -> int:
        """
        Clean old checkpoints, keeping only the most recent ones.
        
        Args:
            agent_id: ID of the agent
            keep_count: Number of checkpoints to keep
            
        Returns:
            Number of checkpoints removed
        """
        store = self._get_agent_store(agent_id)
        
        checkpoints = self.list_checkpoints(agent_id)
        
        if len(checkpoints) <= keep_count:
            return 0
        
        # Sort checkpoints by version number
        checkpoints.sort(key=lambda cp: int(cp[1:]) if cp.startswith('v') else 0)
        
        # Remove oldest checkpoints
        to_remove = checkpoints[:-keep_count]
        removed = 0
        
        for checkpoint in to_remove:
            if store.delete(checkpoint):
                removed += 1
        
        return removed


# Run basic tests to validate memory components
def test_memory_store():
    """Test memory store functionality."""
    try:
        print("Creating InMemoryStore...")
        store = InMemoryStore()
        
        print("Storing test value...")
        store.store("test_key", "test_value")
        
        print("Retrieving test value...")
        value = store.retrieve("test_key")
        
        print(f"Retrieved value: {value}")
        
        # Check that the value matches
        return value == "test_value"
    except Exception as e:
        import traceback
        print(f"Error details: {str(e)}")
        traceback.print_exc()
        return False


def test_persistent_store():
    """Test persistent store functionality."""
    store = PersistentStore("data/test")
    
    # Store a value
    store.store("test_key", "test_value")
    
    # Retrieve the value
    value = store.retrieve("test_key")
    
    # Delete the test file
    store.delete("test_key")
    
    # Check that the value matches
    return value == "test_value"


def test_json_store():
    """Test JSON store functionality."""
    store = JsonStore("data/test")
    
    # Store a dictionary
    test_data = {"name": "Test", "value": 42}
    store.store("test_json", test_data)
    
    # Retrieve the dictionary
    value = store.retrieve("test_json")
    
    # Delete the test file
    store.delete("test_json")
    
    # Check that the value matches
    return value == test_data


def test_agent_memory():
    """Test agent memory functionality."""
    try:
        print("Creating AgentMemory...")
        memory = AgentMemory("test_agent")
        
        print("Testing short-term memory...")
        memory.remember("short_key", "short_value")
        short_value = memory.recall("short_key")
        print(f"Short-term value: {short_value}")
        
        print("Testing long-term memory...")
        memory.memorize("long_key", "long_value")
        long_value = memory.recollect("long_key")
        print(f"Long-term value: {long_value}")
        
        print("Creating conversation...")
        conversation_id = memory.create_conversation()
        
        print("Creating message...")
        # Look closely at how MessageContent and AgentMessage are instantiated
        message_content = MessageContent(
            type=MessageType.QUERY,
            content="Test message"
        )
        print(f"Message content created: {message_content}")
        
        message = AgentMessage(
            sender="test_agent",
            receiver="test_receiver",
            content=message_content
        )
        print(f"Message created: {message}")
        
        print("Adding message to conversation...")
        memory.add_message_to_conversation(message, conversation_id)
        
        print("Getting conversation...")
        conversation = memory.get_conversation(conversation_id)
        
        # Cleanup
        memory.forget("short_key")
        memory.forget("long_key")
        
        # Check results
        return (short_value == "short_value" and
                long_value == "long_value" and
                len(conversation["messages"]) == 1)
    except Exception as e:
        import traceback
        print(f"Error details: {str(e)}")
        traceback.print_exc()
        return False


def test_state_manager():
    """Test state manager functionality."""
    state_manager = StateManager("data/test_state")
    
    # Save state
    test_state = {"status": "active", "count": 42}
    state_manager.save_state("test_agent", test_state, checkpoint=True)
    
    # Load state
    loaded_state = state_manager.load_state("test_agent")
    
    # Get checkpoints
    checkpoints = state_manager.list_checkpoints("test_agent")
    
    # Cleanup
    for checkpoint in checkpoints:
        state_manager._get_agent_store("test_agent").delete(checkpoint)
    state_manager._get_agent_store("test_agent").delete("current")
    
    # Check results
    return (loaded_state.get("status") == "active" and
            loaded_state.get("count") == 42 and
            len(checkpoints) == 1)


# Run tests if this file is executed directly
if __name__ == "__main__":
    print("Testing Core Agent Framework - State and Memory")
    
    tests = [
        ("memory_store", test_memory_store),
        ("persistent_store", test_persistent_store),
        ("json_store", test_json_store),
        ("agent_memory", test_agent_memory),
        ("state_manager", test_state_manager)
    ]
    
    success_count = 0
    
    for name, test_func in tests:
        print(f"Running test: {name}...", end=" ")
        try:
            result = test_func()
            if result:
                print("✅ PASS")
                success_count += 1
            else:
                print("❌ FAIL")
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
    
    print(f"\nTests complete: {success_count}/{len(tests)} passed.")