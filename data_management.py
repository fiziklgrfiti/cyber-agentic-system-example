"""
Security Capability Measurement Program - Phase 1 Implementation
Milestone 4: Data Management Layer

This module implements the data management layer for security metrics,
including connectors, normalization, and validation mechanisms.
"""

import os
import sys
import csv
import json
import time
import uuid
import logging
import datetime
import sqlite3
import hashlib
import re
from typing import Dict, List, Any, Tuple, Optional, Union, Set, TypeVar, Generic, Callable
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager
import xml.etree.ElementTree as ET

# Try to import components from previous milestones
try:
    from base_structure import logger, MessageType # milestone 1
    from state_and_memory import InMemoryStore, PersistentStore, JsonStore # milestone 3
except ImportError:
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
    
    # Minimal versions for standalone testing
    class MessageType(str, Enum):
        """Enumeration of message types for agent communication."""
        QUERY = "query"
        RESPONSE = "response"
        REQUEST = "request"
        NOTIFICATION = "notification"
        ERROR = "error"
        RESULT = "result"
        COMMAND = "command"
        STATUS = "status"
    
    class InMemoryStore:
        """Stub for InMemoryStore for standalone testing."""
        def __init__(self):
            self.store = {}
        
        def store(self, key, value):
            self.store[key] = value
            return True
        
        def retrieve(self, key, default=None):
            return self.store.get(key, default)

    class PersistentStore:
        """Stub for PersistentStore for standalone testing."""
        def __init__(self, directory):
            self.store = {}
            self.directory = directory
        
        def store(self, key, value):
            self.store[key] = value
            return True
        
        def retrieve(self, key, default=None):
            return self.store.get(key, default)

    class JsonStore:
        """Stub for JsonStore for standalone testing."""
        def __init__(self, directory):
            self.store = {}
            self.directory = directory
        
        def store(self, key, value):
            self.store[key] = value
            return True
        
        def retrieve(self, key, default=None):
            return self.store.get(key, default)

# Create data directories
os.makedirs("data/metrics", exist_ok=True)
os.makedirs("data/sources", exist_ok=True)
os.makedirs("data/schemas", exist_ok=True)


class MetricType(str, Enum):
    """Types of security metrics based on NIST SP 800-55."""
    IMPLEMENTATION = "implementation"
    EFFECTIVENESS = "effectiveness"
    EFFICIENCY = "efficiency"
    IMPACT = "impact"
    UNKNOWN = "unknown"


class MetricStatus(str, Enum):
    """Status of a security metric."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEPRECATED = "deprecated"
    PROPOSED = "proposed"
    UNDER_REVIEW = "under_review"


class DataSourceType(str, Enum):
    """Types of data sources."""
    CSV = "csv"
    JSON = "json"
    XML = "xml"
    SQL = "sql"
    API = "api"
    MANUAL = "manual"
    OTHER = "other"


@dataclass
class MetricDefinition:
    """Definition of a security metric based on NIST SP 800-55."""
    id: str
    name: str
    description: str
    type: MetricType
    formula: str
    unit: str
    target: Any = None
    frequency: str = "monthly"
    responsible: str = ""
    data_source: str = ""
    status: MetricStatus = MetricStatus.ACTIVE
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MetricDefinition':
        """Create from dictionary."""
        # Convert string to enum for type and status
        if isinstance(data.get("type"), str):
            data["type"] = MetricType(data["type"])
        
        if isinstance(data.get("status"), str):
            data["status"] = MetricStatus(data["status"])
        
        return cls(**data)


@dataclass
class MetricValue:
    """Value of a security metric at a specific point in time."""
    metric_id: str
    value: Any
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    source: str = ""
    collection_method: str = ""
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MetricValue':
        """Create from dictionary."""
        return cls(**data)


@dataclass
class DataSourceDefinition:
    """Definition of a data source."""
    id: str
    name: str
    type: DataSourceType
    location: str
    description: str = ""
    credentials: Dict[str, Any] = field(default_factory=dict)
    schedule: str = ""
    configuration: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        
        # Convert enum to string
        if isinstance(result["type"], DataSourceType):
            result["type"] = result["type"].value
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DataSourceDefinition':
        """Create from dictionary."""
        # Convert string to enum for type
        if isinstance(data.get("type"), str):
            data["type"] = DataSourceType(data["type"])
        
        return cls(**data)


class DataConnector(ABC):
    """
    Abstract base class for data connectors.
    Provides an interface for connecting to different data sources.
    """
    
    @abstractmethod
    def connect(self) -> bool:
        """
        Establish connection to the data source.
        
        Returns:
            Boolean indicating success
        """
        pass
    
    @abstractmethod
    def disconnect(self) -> bool:
        """
        Close connection to the data source.
        
        Returns:
            Boolean indicating success
        """
        pass
    
    @abstractmethod
    def fetch_data(self, query: Any) -> List[Dict[str, Any]]:
        """
        Fetch data from the data source.
        
        Args:
            query: Query or parameters to fetch data
            
        Returns:
            List of data records
        """
        pass
    
    @abstractmethod
    def get_schema(self) -> Dict[str, Any]:
        """
        Get schema of the data source.
        
        Returns:
            Schema information
        """
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connection to the data source.
        
        Returns:
            Boolean indicating success
        """
        pass


class CsvConnector(DataConnector):
    """
    Connector for CSV data sources.
    """
    
    def __init__(self, file_path: str, delimiter: str = ',', has_header: bool = True):
        """
        Initialize CSV connector.
        
        Args:
            file_path: Path to the CSV file
            delimiter: Delimiter used in the CSV file
            has_header: Whether the CSV file has a header row
        """
        self.file_path = file_path
        self.delimiter = delimiter
        self.has_header = has_header
        self.headers = []
        self.connected = False
        
        logger.debug(f"CsvConnector initialized for {file_path}")
    
    def connect(self) -> bool:
        """Establish connection to the CSV file."""
        try:
            if not os.path.exists(self.file_path):
                logger.error(f"CSV file not found: {self.file_path}")
                return False
            
            with open(self.file_path, 'r', newline='') as csvfile:
                reader = csv.reader(csvfile, delimiter=self.delimiter)
                
                if self.has_header:
                    self.headers = next(reader)
                
                self.connected = True
                logger.debug(f"Connected to CSV file: {self.file_path}")
                
                return True
                
        except Exception as e:
            logger.error(f"Error connecting to CSV file: {str(e)}")
            return False
    
    def disconnect(self) -> bool:
        """Close connection to the CSV file."""
        # No actual connection to close for CSV files
        self.connected = False
        return True
    
    def fetch_data(self, query: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Fetch data from the CSV file.
        
        Args:
            query: Optional filter criteria
            
        Returns:
            List of data records
        """
        if not self.connected:
            if not self.connect():
                return []
        
        try:
            results = []
            
            with open(self.file_path, 'r', newline='') as csvfile:
                if self.has_header:
                    reader = csv.DictReader(csvfile, delimiter=self.delimiter)
                else:
                    reader = csv.reader(csvfile, delimiter=self.delimiter)
                
                for row in reader:
                    # Convert to dict if we don't have headers
                    if not self.has_header:
                        row_dict = {str(i): val for i, val in enumerate(row)}
                    else:
                        row_dict = row
                    
                    # Apply filters if provided
                    if query:
                        include = True
                        for key, value in query.items():
                            if key in row_dict and row_dict[key] != value:
                                include = False
                                break
                        
                        if not include:
                            continue
                    
                    results.append(row_dict)
            
            return results
            
        except Exception as e:
            logger.error(f"Error fetching data from CSV file: {str(e)}")
            return []
    
    def get_schema(self) -> Dict[str, Any]:
        """Get schema of the CSV file."""
        if not self.connected:
            if not self.connect():
                return {}
        
        try:
            # Get a sample of the data to determine types
            sample_rows = self.fetch_data()[:10]
            
            schema = {
                "type": "csv",
                "has_header": self.has_header,
                "columns": []
            }
            
            if not sample_rows:
                return schema
            
            # Use headers if available, otherwise use column indices
            column_names = self.headers if self.has_header else [str(i) for i in range(len(next(iter(sample_rows)).keys()))]
            
            for column in column_names:
                column_info = {
                    "name": column,
                    "type": "string",  # Default type
                    "sample_values": []
                }
                
                # Try to determine column type from sample data
                numeric_count = 0
                date_count = 0
                bool_count = 0
                
                for row in sample_rows:
                    value = row.get(column, "")
                    column_info["sample_values"].append(value)
                    
                    # Count types
                    if self._is_numeric(value):
                        numeric_count += 1
                    elif self._is_date(value):
                        date_count += 1
                    elif self._is_boolean(value):
                        bool_count += 1
                
                # Determine predominant type
                row_count = len(sample_rows)
                if numeric_count > row_count * 0.7:
                    column_info["type"] = "numeric"
                elif date_count > row_count * 0.7:
                    column_info["type"] = "date"
                elif bool_count > row_count * 0.7:
                    column_info["type"] = "boolean"
                
                schema["columns"].append(column_info)
            
            return schema
            
        except Exception as e:
            logger.error(f"Error getting schema from CSV file: {str(e)}")
            return {}
    
    def test_connection(self) -> bool:
        """Test connection to the CSV file."""
        # For CSV, just check if the file exists and is readable
        try:
            if not os.path.exists(self.file_path):
                return False
            
            with open(self.file_path, 'r') as f:
                # Try to read a line
                f.readline()
            
            return True
        except Exception:
            return False
    
    def _is_numeric(self, value: str) -> bool:
        """Check if a value is numeric."""
        try:
            float(value)
            return True
        except (ValueError, TypeError):
            return False
    
    def _is_date(self, value: str) -> bool:
        """Check if a value is a date."""
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'\d{2}/\d{2}/\d{4}',  # MM/DD/YYYY
            r'\d{2}\.\d{2}\.\d{4}'  # DD.MM.YYYY
        ]
        
        for pattern in date_patterns:
            if re.match(pattern, str(value)):
                return True
        
        return False
    
    def _is_boolean(self, value: str) -> bool:
        """Check if a value is a boolean."""
        if isinstance(value, bool):
            return True
        
        bool_values = ['true', 'false', 'yes', 'no', '0', '1', 't', 'f', 'y', 'n']
        return str(value).lower() in bool_values


class JsonConnector(DataConnector):
    """
    Connector for JSON data sources.
    """
    
    def __init__(self, file_path: str, root_path: str = None):
        """
        Initialize JSON connector.
        
        Args:
            file_path: Path to the JSON file
            root_path: JSON path to the root element containing data
        """
        self.file_path = file_path
        self.root_path = root_path
        self.data = None
        self.connected = False
        
        logger.debug(f"JsonConnector initialized for {file_path}")
    
    def connect(self) -> bool:
        """Establish connection to the JSON file."""
        try:
            if not os.path.exists(self.file_path):
                logger.error(f"JSON file not found: {self.file_path}")
                return False
            
            with open(self.file_path, 'r') as jsonfile:
                self.data = json.load(jsonfile)
            
            # Navigate to root path if specified
            if self.root_path:
                current = self.data
                for key in self.root_path.split('.'):
                    if key in current:
                        current = current[key]
                    else:
                        logger.error(f"Root path {self.root_path} not found in JSON data")
                        return False
                
                self.data = current
            
            self.connected = True
            logger.debug(f"Connected to JSON file: {self.file_path}")
            
            return True
                
        except Exception as e:
            logger.error(f"Error connecting to JSON file: {str(e)}")
            return False
    
    def disconnect(self) -> bool:
        """Close connection to the JSON file."""
        self.data = None
        self.connected = False
        return True
    
    def fetch_data(self, query: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Fetch data from the JSON file.
        
        Args:
            query: Optional filter criteria
            
        Returns:
            List of data records
        """
        if not self.connected:
            if not self.connect():
                return []
        
        try:
            results = []
            
            # Ensure data is a list of dictionaries
            if isinstance(self.data, list):
                data_list = self.data
            elif isinstance(self.data, dict):
                # Try to find the first list in the dictionary
                for key, value in self.data.items():
                    if isinstance(value, list):
                        data_list = value
                        break
                else:
                    # If no list found, wrap the dictionary in a list
                    data_list = [self.data]
            else:
                logger.error(f"Unexpected JSON data format: {type(self.data)}")
                return []
            
            # Process each record
            for item in data_list:
                if not isinstance(item, dict):
                    continue
                
                # Apply filters if provided
                if query:
                    include = True
                    for key, value in query.items():
                        if key in item and item[key] != value:
                            include = False
                            break
                    
                    if not include:
                        continue
                
                results.append(item)
            
            return results
            
        except Exception as e:
            logger.error(f"Error fetching data from JSON file: {str(e)}")
            return []
    
    def get_schema(self) -> Dict[str, Any]:
        """Get schema of the JSON file."""
        if not self.connected:
            if not self.connect():
                return {}
        
        try:
            schema = {
                "type": "json",
                "fields": []
            }
            
            # Get a sample record to infer schema
            sample_data = self.fetch_data()[:1]
            
            if not sample_data:
                return schema
            
            sample = sample_data[0]
            
            # Build schema from sample
            for key, value in sample.items():
                field_type = self._get_json_type(value)
                
                field_info = {
                    "name": key,
                    "type": field_type,
                    "sample_value": value
                }
                
                # Add nested fields for objects
                if field_type == "object" and isinstance(value, dict):
                    field_info["nested_fields"] = []
                    for nested_key, nested_value in value.items():
                        field_info["nested_fields"].append({
                            "name": nested_key,
                            "type": self._get_json_type(nested_value),
                            "sample_value": nested_value
                        })
                
                # Add item type for arrays
                if field_type == "array" and isinstance(value, list) and value:
                    field_info["item_type"] = self._get_json_type(value[0])
                    field_info["sample_item"] = value[0] if value else None
                
                schema["fields"].append(field_info)
            
            return schema
            
        except Exception as e:
            logger.error(f"Error getting schema from JSON file: {str(e)}")
            return {}
    
    def test_connection(self) -> bool:
        """Test connection to the JSON file."""
        try:
            if not os.path.exists(self.file_path):
                return False
            
            with open(self.file_path, 'r') as f:
                # Try to parse JSON
                json.load(f)
            
            return True
        except Exception:
            return False
    
    def _get_json_type(self, value: Any) -> str:
        """Get the JSON type of a value."""
        if value is None:
            return "null"
        elif isinstance(value, bool):
            return "boolean"
        elif isinstance(value, int) or isinstance(value, float):
            return "number"
        elif isinstance(value, str):
            return "string"
        elif isinstance(value, list):
            return "array"
        elif isinstance(value, dict):
            return "object"
        else:
            return "unknown"


class SqliteConnector(DataConnector):
    """
    Connector for SQLite databases.
    """
    
    def __init__(self, database_path: str):
        """
        Initialize SQLite connector.
        
        Args:
            database_path: Path to the SQLite database file
        """
        self.database_path = database_path
        self.connection = None
        self.connected = False
        
        logger.debug(f"SqliteConnector initialized for {database_path}")
    
    def connect(self) -> bool:
        """Establish connection to the SQLite database."""
        try:
            self.connection = sqlite3.connect(self.database_path)
            self.connected = True
            logger.debug(f"Connected to SQLite database: {self.database_path}")
            return True
                
        except Exception as e:
            logger.error(f"Error connecting to SQLite database: {str(e)}")
            return False
    
    def disconnect(self) -> bool:
        """Close connection to the SQLite database."""
        if self.connection:
            try:
                self.connection.close()
                self.connection = None
                self.connected = False
                return True
            except Exception as e:
                logger.error(f"Error disconnecting from SQLite database: {str(e)}")
                return False
        
        return True
    
    def fetch_data(self, query: str) -> List[Dict[str, Any]]:
        """
        Fetch data from the SQLite database.
        
        Args:
            query: SQL query to execute
            
        Returns:
            List of data records
        """
        if not self.connected:
            if not self.connect():
                return []
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(query)
            
            # Get column names
            columns = [desc[0] for desc in cursor.description]
            
            # Convert rows to dictionaries
            results = []
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            return results
            
        except Exception as e:
            logger.error(f"Error fetching data from SQLite database: {str(e)}")
            return []
    
    def get_schema(self) -> Dict[str, Any]:
        """Get schema of the SQLite database."""
        if not self.connected:
            if not self.connect():
                return {}
        
        try:
            schema = {
                "type": "sqlite",
                "tables": []
            }
            
            cursor = self.connection.cursor()
            
            # Get list of tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [table[0] for table in cursor.fetchall()]
            
            # Get schema for each table
            for table in tables:
                table_schema = {
                    "name": table,
                    "columns": []
                }
                
                # Get column information
                cursor.execute(f"PRAGMA table_info({table});")
                for column_info in cursor.fetchall():
                    col_id, name, dtype, notnull, default_value, pk = column_info
                    
                    table_schema["columns"].append({
                        "name": name,
                        "type": dtype,
                        "not_null": bool(notnull),
                        "default_value": default_value,
                        "primary_key": bool(pk)
                    })
                
                schema["tables"].append(table_schema)
            
            return schema
            
        except Exception as e:
            logger.error(f"Error getting schema from SQLite database: {str(e)}")
            return {}
    
    def test_connection(self) -> bool:
        """Test connection to the SQLite database."""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            cursor.execute("SELECT 1;")
            conn.close()
            return True
        except Exception:
            return False


class DataNormalizer:
    """
    Normalizes data from different sources into a standard format.
    """
    
    def __init__(self):
        """Initialize the data normalizer."""
        self.transformers = {}
        logger.debug("DataNormalizer initialized")
    
    def register_transformer(self, source_type: str, transformer_func: Callable[[Dict[str, Any]], Dict[str, Any]]):
        """
        Register a transformer function for a specific source type.
        
        Args:
            source_type: Type of the source data
            transformer_func: Function to transform the data
        """
        self.transformers[source_type] = transformer_func
        logger.debug(f"Registered transformer for source type: {source_type}")
    
    def normalize(self, data: List[Dict[str, Any]], source_type: str) -> List[Dict[str, Any]]:
        """
        Normalize data to a standard format.
        
        Args:
            data: List of data records to normalize
            source_type: Type of the source data
            
        Returns:
            Normalized data
        """
        if source_type not in self.transformers:
            logger.warning(f"No transformer registered for source type: {source_type}")
            return data
        
        transformer = self.transformers[source_type]
        
        try:
            normalized = [transformer(record) for record in data]
            return normalized
        except Exception as e:
            logger.error(f"Error normalizing data: {str(e)}")
            return data
    
    def normalize_date(self, date_str: str, format_str: str = None) -> Optional[str]:
        """
        Normalize a date string to ISO format.
        
        Args:
            date_str: Date string to normalize
            format_str: Optional format string for parsing
            
        Returns:
            Normalized date string or None if parsing fails
        """
        if not date_str:
            return None
        
        try:
            # Try explicit format if provided
            if format_str:
                dt = datetime.datetime.strptime(date_str, format_str)
                return dt.isoformat()
            
            # Try common formats
            formats = [
                '%Y-%m-%d',
                '%d/%m/%Y',
                '%m/%d/%Y',
                '%Y/%m/%d',
                '%d-%m-%Y',
                '%m-%d-%Y',
                '%d.%m.%Y',
                '%Y-%m-%d %H:%M:%S',
                '%d/%m/%Y %H:%M:%S',
                '%m/%d/%Y %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.datetime.strptime(date_str, fmt)
                    return dt.isoformat()
                except ValueError:
                    continue
            
            # If no format matched, return original string
            return date_str
            
        except Exception:
            return date_str
    
    def normalize_boolean(self, value: Any) -> Optional[bool]:
        """
        Normalize a value to a boolean.
        
        Args:
            value: Value to normalize
            
        Returns:
            Normalized boolean or None if conversion fails
        """
        if value is None:
            return None
        
        if isinstance(value, bool):
            return value
        
        if isinstance(value, (int, float)):
            return bool(value)
        
        if isinstance(value, str):
            true_values = ['true', 'yes', 'y', '1', 't']
            false_values = ['false', 'no', 'n', '0', 'f']
            
            value_lower = value.lower().strip()
            
            if value_lower in true_values:
                return True
            elif value_lower in false_values:
                return False
        
        # If conversion fails, return None
        return None
    
    def normalize_number(self, value: Any) -> Optional[float]:
        """
        Normalize a value to a number.
        
        Args:
            value: Value to normalize
            
        Returns:
            Normalized number or None if conversion fails
        """
        if value is None:
            return None
        
        if isinstance(value, (int, float)):
            return float(value)
        
        if isinstance(value, str):
            try:
                # Remove currency symbols and separators
                cleaned = re.sub(r'[^\d.-]', '', value)
                return float(cleaned)
            except ValueError:
                pass
        
        # If conversion fails, return None
        return None


class DataValidator:
    """
    Validates data against defined constraints and rules.
    """
    
    def __init__(self):
        """Initialize the data validator."""
        self.validation_rules = {}
        logger.debug("DataValidator initialized")
    
    def add_validation_rule(self, field_name: str, rule_func: Callable[[Any], bool], error_message: str):
        """
        Add a validation rule for a field.
        
        Args:
            field_name: Name of the field to validate
            rule_func: Function to validate the field
            error_message: Error message if validation fails
        """
        if field_name not in self.validation_rules:
            self.validation_rules[field_name] = []
        
        self.validation_rules[field_name].append({
            "rule": rule_func,
            "message": error_message
        })
        
        logger.debug(f"Added validation rule for field: {field_name}")
    
    def validate(self, data: Dict[str, Any]) -> List[str]:
        """
        Validate data against all rules.
        
        Args:
            data: Data to validate
            
        Returns:
            List of error messages if validation fails
        """
        errors = []
        
        for field_name, rules in self.validation_rules.items():
            if field_name not in data:
                continue
            
            field_value = data[field_name]
            
            for rule in rules:
                try:
                    if not rule["rule"](field_value):
                        errors.append(f"{field_name}: {rule['message']}")
                except Exception as e:
                    errors.append(f"{field_name}: Validation error - {str(e)}")
        
        return errors
    
    def validate_batch(self, data_list: List[Dict[str, Any]]) -> Dict[int, List[str]]:
        """
        Validate a batch of data records.
        
        Args:
            data_list: List of data records to validate
            
        Returns:
            Dictionary mapping record indices to error messages
        """
        results = {}
        
        for i, data in enumerate(data_list):
            errors = self.validate(data)
            if errors:
                results[i] = errors
        
        return results
    
    # Common validation rules
    
    @staticmethod
    def required(value: Any) -> bool:
        """Validate that a value is not None or empty."""
        if value is None:
            return False
        
        if isinstance(value, str) and not value.strip():
            return False
        
        return True
    
    @staticmethod
    def min_length(min_len: int) -> Callable[[Any], bool]:
        """
        Validate minimum length of a string or collection.
        
        Args:
            min_len: Minimum length required
            
        Returns:
            Validation function
        """
        def validator(value: Any) -> bool:
            if value is None:
                return False
            
            try:
                return len(value) >= min_len
            except (TypeError, AttributeError):
                return False
        
        return validator
    
    @staticmethod
    def max_length(max_len: int) -> Callable[[Any], bool]:
        """
        Validate maximum length of a string or collection.
        
        Args:
            max_len: Maximum length allowed
            
        Returns:
            Validation function
        """
        def validator(value: Any) -> bool:
            if value is None:
                return True
            
            try:
                return len(value) <= max_len
            except (TypeError, AttributeError):
                return True
        
        return validator
    
    @staticmethod
    def pattern(regex: str) -> Callable[[Any], bool]:
        """
        Validate that a string matches a regex pattern.
        
        Args:
            regex: Regular expression pattern
            
        Returns:
            Validation function
        """
        compiled = re.compile(regex)
        
        def validator(value: Any) -> bool:
            if value is None:
                return False
            
            if not isinstance(value, str):
                return False
            
            return bool(compiled.match(value))
        
        return validator
    
    @staticmethod
    def min_value(min_val: Union[int, float]) -> Callable[[Any], bool]:
        """
        Validate minimum numeric value.
        
        Args:
            min_val: Minimum value allowed
            
        Returns:
            Validation function
        """
        def validator(value: Any) -> bool:
            if value is None:
                return False
            
            try:
                return float(value) >= min_val
            except (ValueError, TypeError):
                return False
        
        return validator
    
    @staticmethod
    def max_value(max_val: Union[int, float]) -> Callable[[Any], bool]:
        """
        Validate maximum numeric value.
        
        Args:
            max_val: Maximum value allowed
            
        Returns:
            Validation function
        """
        def validator(value: Any) -> bool:
            if value is None:
                return True
            
            try:
                return float(value) <= max_val
            except (ValueError, TypeError):
                return True
        
        return validator


class MetricManager:
    """
    Manages security metrics, including definitions and values.
    Provides CRUD operations for metrics and handles persistence.
    """
    
    def __init__(self, storage_path: str = "data/metrics"):
        """
        Initialize metric manager.
        
        Args:
            storage_path: Path for metric storage
        """
        self.storage_path = Path(storage_path)
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Create stores for metric definitions and values
        self.definitions_store = JsonStore(str(self.storage_path / "definitions"))
        self.values_store = JsonStore(str(self.storage_path / "values"))
        
        logger.info(f"MetricManager initialized in {storage_path}")
    
    def create_metric(self, metric: MetricDefinition) -> bool:
        """
        Create a new metric definition.
        
        Args:
            metric: Metric definition
            
        Returns:
            Boolean indicating success
        """
        # Check if metric already exists
        if self.definitions_store.contains(metric.id):
            logger.warning(f"Metric {metric.id} already exists")
            return False
        
        # Store metric definition
        metric.created_at = datetime.datetime.now().isoformat()
        metric.updated_at = metric.created_at
        
        return self.definitions_store.store(metric.id, metric.to_dict())
    
    def get_metric(self, metric_id: str) -> Optional[MetricDefinition]:
        """
        Get a metric definition.
        
        Args:
            metric_id: ID of the metric
            
        Returns:
            Metric definition or None if not found
        """
        data = self.definitions_store.retrieve(metric_id)
        
        if data is None:
            return None
        
        return MetricDefinition.from_dict(data)
    
    def update_metric(self, metric: MetricDefinition) -> bool:
        """
        Update a metric definition.
        
        Args:
            metric: Updated metric definition
            
        Returns:
            Boolean indicating success
        """
        # Check if metric exists
        if not self.definitions_store.contains(metric.id):
            logger.warning(f"Metric {metric.id} does not exist")
            return False
        
        # Get existing metric
        existing = self.get_metric(metric.id)
        
        # Update only the fields that have changed
        metric.created_at = existing.created_at
        metric.updated_at = datetime.datetime.now().isoformat()
        
        return self.definitions_store.store(metric.id, metric.to_dict())
    
    def delete_metric(self, metric_id: str) -> bool:
        """
        Delete a metric definition.
        
        Args:
            metric_id: ID of the metric
            
        Returns:
            Boolean indicating success
        """
        # Delete metric definition
        if not self.definitions_store.delete(metric_id):
            return False
        
        # Delete all metric values
        values_prefix = f"{metric_id}_"
        for key in self.values_store.get_all_keys():
            if key.startswith(values_prefix):
                self.values_store.delete(key)
        
        return True
    
    def list_metrics(self, type_filter: Optional[MetricType] = None, status_filter: Optional[MetricStatus] = None) -> List[MetricDefinition]:
        """
        List all metric definitions, optionally filtered.
        
        Args:
            type_filter: Optional filter by metric type
            status_filter: Optional filter by metric status
            
        Returns:
            List of metric definitions
        """
        metrics = []
        
        for key in self.definitions_store.get_all_keys():
            data = self.definitions_store.retrieve(key)
            
            if data is None:
                continue
            
            metric = MetricDefinition.from_dict(data)
            
            # Apply filters
            if type_filter and metric.type != type_filter:
                continue
            
            if status_filter and metric.status != status_filter:
                continue
            
            metrics.append(metric)
        
        return metrics
    
    def add_metric_value(self, value: MetricValue) -> bool:
        """
        Add a metric value.
        
        Args:
            value: Metric value
            
        Returns:
            Boolean indicating success
        """
        # Check if metric exists
        if not self.definitions_store.contains(value.metric_id):
            logger.warning(f"Metric {value.metric_id} does not exist")
            return False
        
        # Create a unique key for the value
        timestamp = value.timestamp.replace(":", "").replace("-", "").replace(".", "")
        value_key = f"{value.metric_id}_{timestamp}"
        
        return self.values_store.store(value_key, value.to_dict())
    
    def get_metric_values(self, metric_id: str, start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[MetricValue]:
        """
        Get values for a specific metric, optionally filtered by date range.
        
        Args:
            metric_id: ID of the metric
            start_date: Optional start date for filtering (ISO format)
            end_date: Optional end date for filtering (ISO format)
            
        Returns:
            List of metric values
        """
        values = []
        prefix = f"{metric_id}_"
        
        for key in self.values_store.get_all_keys():
            if not key.startswith(prefix):
                continue
            
            data = self.values_store.retrieve(key)
            
            if data is None:
                continue
            
            value = MetricValue.from_dict(data)
            
            # Apply date filters
            if start_date and value.timestamp < start_date:
                continue
            
            if end_date and value.timestamp > end_date:
                continue
            
            values.append(value)
        
        # Sort by timestamp
        values.sort(key=lambda v: v.timestamp)
        
        return values
    
    def get_latest_metric_value(self, metric_id: str) -> Optional[MetricValue]:
        """
        Get the latest value for a specific metric.
        
        Args:
            metric_id: ID of the metric
            
        Returns:
            Latest metric value or None if not found
        """
        values = self.get_metric_values(metric_id)
        
        if not values:
            return None
        
        return values[-1]


class DataSourceManager:
    """
    Manages data sources for security metrics.
    Provides CRUD operations for data sources and handles connections.
    """
    
    def __init__(self, storage_path: str = "data/sources"):
        """
        Initialize data source manager.
        
        Args:
            storage_path: Path for data source storage
        """
        self.storage_path = Path(storage_path)
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Create store for data source definitions
        self.definitions_store = JsonStore(str(self.storage_path))
        
        # Cache of active connectors
        self.active_connectors = {}
        
        logger.info(f"DataSourceManager initialized in {storage_path}")
    
    def create_data_source(self, source: DataSourceDefinition) -> bool:
        """
        Create a new data source definition.
        
        Args:
            source: Data source definition
            
        Returns:
            Boolean indicating success
        """
        # Check if data source already exists
        if self.definitions_store.contains(source.id):
            logger.warning(f"Data source {source.id} already exists")
            return False
        
        return self.definitions_store.store(source.id, source.to_dict())
    
    def get_data_source(self, source_id: str) -> Optional[DataSourceDefinition]:
        """
        Get a data source definition.
        
        Args:
            source_id: ID of the data source
            
        Returns:
            Data source definition or None if not found
        """
        data = self.definitions_store.retrieve(source_id)
        
        if data is None:
            return None
        
        return DataSourceDefinition.from_dict(data)
    
    def update_data_source(self, source: DataSourceDefinition) -> bool:
        """
        Update a data source definition.
        
        Args:
            source: Updated data source definition
            
        Returns:
            Boolean indicating success
        """
        # Check if data source exists
        if not self.definitions_store.contains(source.id):
            logger.warning(f"Data source {source.id} does not exist")
            return False
        
        # Check if connector is active
        if source.id in self.active_connectors:
            # Disconnect before updating
            connector = self.active_connectors[source.id]
            connector.disconnect()
            del self.active_connectors[source.id]
        
        return self.definitions_store.store(source.id, source.to_dict())
    
    def delete_data_source(self, source_id: str) -> bool:
        """
        Delete a data source definition.
        
        Args:
            source_id: ID of the data source
            
        Returns:
            Boolean indicating success
        """
        # Check if connector is active
        if source_id in self.active_connectors:
            # Disconnect before deleting
            connector = self.active_connectors[source_id]
            connector.disconnect()
            del self.active_connectors[source_id]
        
        return self.definitions_store.delete(source_id)
    
    def list_data_sources(self, type_filter: Optional[DataSourceType] = None) -> List[DataSourceDefinition]:
        """
        List all data source definitions, optionally filtered by type.
        
        Args:
            type_filter: Optional filter by data source type
            
        Returns:
            List of data source definitions
        """
        sources = []
        
        for key in self.definitions_store.get_all_keys():
            data = self.definitions_store.retrieve(key)
            
            if data is None:
                continue
            
            source = DataSourceDefinition.from_dict(data)
            
            # Apply filter
            if type_filter and source.type != type_filter:
                continue
            
            sources.append(source)
        
        return sources
    
    def get_connector(self, source_id: str) -> Optional[DataConnector]:
        """
        Get a connector for a data source.
        
        Args:
            source_id: ID of the data source
            
        Returns:
            Data connector or None if not found or not supported
        """
        # Check if connector is already active
        if source_id in self.active_connectors:
            return self.active_connectors[source_id]
        
        # Get data source definition
        source = self.get_data_source(source_id)
        
        if source is None:
            logger.warning(f"Data source {source_id} not found")
            return None
        
        # Create connector based on source type
        connector = None
        
        if source.type == DataSourceType.CSV:
            connector = CsvConnector(
                file_path=source.location,
                delimiter=source.configuration.get("delimiter", ","),
                has_header=source.configuration.get("has_header", True)
            )
        
        elif source.type == DataSourceType.JSON:
            connector = JsonConnector(
                file_path=source.location,
                root_path=source.configuration.get("root_path")
            )
        
        elif source.type == DataSourceType.SQL:
            connector = SqliteConnector(
                database_path=source.location
            )
        
        else:
            logger.warning(f"Unsupported data source type: {source.type}")
            return None
        
        # Try to connect
        if connector.connect():
            self.active_connectors[source_id] = connector
            return connector
        
        return None
    
    def test_data_source(self, source_id: str) -> bool:
        """
        Test connection to a data source.
        
        Args:
            source_id: ID of the data source
            
        Returns:
            Boolean indicating success
        """
        # Get data source definition
        source = self.get_data_source(source_id)
        
        if source is None:
            logger.warning(f"Data source {source_id} not found")
            return False
        
        # Create temporary connector
        connector = None
        
        if source.type == DataSourceType.CSV:
            connector = CsvConnector(
                file_path=source.location,
                delimiter=source.configuration.get("delimiter", ","),
                has_header=source.configuration.get("has_header", True)
            )
        
        elif source.type == DataSourceType.JSON:
            connector = JsonConnector(
                file_path=source.location,
                root_path=source.configuration.get("root_path")
            )
        
        elif source.type == DataSourceType.SQL:
            connector = SqliteConnector(
                database_path=source.location
            )
        
        else:
            logger.warning(f"Unsupported data source type: {source.type}")
            return False
        
        # Test connection
        result = connector.test_connection()
        
        # Clean up
        connector.disconnect()
        
        return result
    
    def fetch_data(self, source_id: str, query: Any = None) -> List[Dict[str, Any]]:
        """
        Fetch data from a data source.
        
        Args:
            source_id: ID of the data source
            query: Query or parameters to fetch data
            
        Returns:
            List of data records
        """
        connector = self.get_connector(source_id)
        
        if connector is None:
            logger.warning(f"Failed to get connector for data source {source_id}")
            return []
        
        return connector.fetch_data(query)
    
    def close_all_connections(self):
        """Close all active connections."""
        for source_id, connector in list(self.active_connectors.items()):
            connector.disconnect()
            del self.active_connectors[source_id]
    
    def __del__(self):
        """Clean up resources when the object is destroyed."""
        self.close_all_connections()


# Run basic tests to validate data management components
def test_csv_connector():
    """Test CSV connector functionality."""
    # Create a test CSV file
    test_file = "data/test_data.csv"
    with open(test_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["id", "name", "value"])
        writer.writerow(["1", "Test 1", "100"])
        writer.writerow(["2", "Test 2", "200"])
    
    # Create connector
    connector = CsvConnector(test_file)
    
    # Test connection
    connect_result = connector.connect()
    
    # Test fetch data
    data = connector.fetch_data()
    
    # Test schema
    schema = connector.get_schema()
    
    # Clean up
    connector.disconnect()
    os.remove(test_file)
    
    # Check results
    return (connect_result and
            len(data) == 2 and
            data[0]["id"] == "1" and
            "columns" in schema)


def test_json_connector():
    """Test JSON connector functionality."""
    # Create a test JSON file
    test_file = "data/test_data.json"
    test_data = {
        "items": [
            {"id": 1, "name": "Test 1", "value": 100},
            {"id": 2, "name": "Test 2", "value": 200}
        ]
    }
    
    with open(test_file, 'w') as f:
        json.dump(test_data, f)
    
    # Create connector
    connector = JsonConnector(test_file, root_path="items")
    
    # Test connection
    connect_result = connector.connect()
    
    # Test fetch data
    data = connector.fetch_data()
    
    # Test schema
    schema = connector.get_schema()
    
    # Clean up
    connector.disconnect()
    os.remove(test_file)
    
    # Check results
    return (connect_result and
            len(data) == 2 and
            data[0]["id"] == 1 and
            "fields" in schema)


def test_data_normalizer():
    """Test data normalizer functionality."""
    normalizer = DataNormalizer()
    
    # Register a transformer
    def transform_test_data(record):
        return {
            "identifier": record.get("id"),
            "full_name": record.get("name"),
            "numeric_value": float(record.get("value", 0))
        }
    
    normalizer.register_transformer("test", transform_test_data)
    
    # Test data
    test_data = [
        {"id": "1", "name": "Test 1", "value": "100"},
        {"id": "2", "name": "Test 2", "value": "200"}
    ]
    
    # Normalize data
    normalized = normalizer.normalize(test_data, "test")
    
    # Check results
    return (len(normalized) == 2 and
            normalized[0]["identifier"] == "1" and
            normalized[0]["numeric_value"] == 100.0)


def test_data_validator():
    """Test data validator functionality."""
    validator = DataValidator()
    
    # Add validation rules
    validator.add_validation_rule("id", DataValidator.required, "ID is required")
    validator.add_validation_rule("name", DataValidator.min_length(3), "Name must be at least 3 characters")
    validator.add_validation_rule("value", DataValidator.min_value(0), "Value must be non-negative")
    
    # Test data
    valid_data = {"id": "1", "name": "Test", "value": 100}
    invalid_data = {"id": "", "name": "Te", "value": -10}
    
    # Validate data
    valid_errors = validator.validate(valid_data)
    invalid_errors = validator.validate(invalid_data)
    
    # Check results
    return (len(valid_errors) == 0 and
            len(invalid_errors) == 3)


def test_metric_manager():
    """Test metric manager functionality."""
    manager = MetricManager("data/test_metrics")
    
    # Create a test metric
    metric = MetricDefinition(
        id="test_metric",
        name="Test Metric",
        description="A test metric",
        type=MetricType.IMPLEMENTATION,
        formula="count(x)",
        unit="count"
    )
    
    # Create metric
    create_result = manager.create_metric(metric)
    
    # Get metric
    retrieved = manager.get_metric("test_metric")
    
    # Add a value
    value = MetricValue(
        metric_id="test_metric",
        value=42
    )
    
    add_value_result = manager.add_metric_value(value)
    
    # Get values
    values = manager.get_metric_values("test_metric")
    
    # Clean up
    manager.delete_metric("test_metric")
    
    # Check results
    return (create_result and
            retrieved is not None and
            retrieved.name == "Test Metric" and
            add_value_result and
            len(values) == 1 and
            values[0].value == 42)


def test_data_source_manager():
    """Test data source manager functionality."""
    manager = DataSourceManager("data/test_sources")
    
    # Create a test CSV file
    test_file = "data/test_data.csv"
    with open(test_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["id", "name", "value"])
        writer.writerow(["1", "Test 1", "100"])
    
    # Create a data source
    source = DataSourceDefinition(
        id="test_source",
        name="Test Source",
        type=DataSourceType.CSV,
        location=test_file,
        configuration={"has_header": True}
    )
    
    # Create data source
    create_result = manager.create_data_source(source)
    
    # Get data source
    retrieved = manager.get_data_source("test_source")
    
    # Get connector
    connector = manager.get_connector("test_source")
    
    # Fetch data
    data = manager.fetch_data("test_source")
    
    # Test connection
    test_result = manager.test_data_source("test_source")
    
    # Clean up
    manager.delete_data_source("test_source")
    os.remove(test_file)
    
    # Check results
    return (create_result and
            retrieved is not None and
            retrieved.name == "Test Source" and
            connector is not None and
            len(data) == 1 and
            test_result)


# Run tests if this file is executed directly
if __name__ == "__main__":
    print("Testing Data Management Layer")
    
    tests = [
        ("csv_connector", test_csv_connector),
        ("json_connector", test_json_connector),
        ("data_normalizer", test_data_normalizer),
        ("data_validator", test_data_validator),
        ("metric_manager", test_metric_manager),
        ("data_source_manager", test_data_source_manager)
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