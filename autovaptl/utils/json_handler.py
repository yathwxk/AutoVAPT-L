"""
JSON handling utilities for AutoVAPT-L.
"""

import json
from typing import Any, Dict, List, Set


class CustomJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder that can handle sets and other custom types.
    """
    
    def default(self, obj):
        """
        Handle special types for JSON serialization.
        
        Args:
            obj: The object to serialize.
            
        Returns:
            A JSON serializable version of the object.
        """
        if isinstance(obj, set):
            return list(obj)
        # Add more type handling here if needed
        return super().default(obj)


def convert_sets_to_lists(obj: Any) -> Any:
    """
    Recursively convert sets to lists in dictionaries and lists.
    
    Args:
        obj: The object to convert.
        
    Returns:
        The object with sets converted to lists.
    """
    if isinstance(obj, dict):
        return {k: convert_sets_to_lists(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_sets_to_lists(x) for x in obj]
    elif isinstance(obj, set):
        return [convert_sets_to_lists(x) for x in obj]
    else:
        return obj


def save_json(data: Any, file_path: str, indent: int = 2) -> None:
    """
    Save data to a JSON file with set handling.
    
    Args:
        data: The data to save.
        file_path: The path to the output file.
        indent: Indentation level for JSON pretty-printing.
    """
    # First, convert all sets to lists recursively
    cleaned_data = convert_sets_to_lists(data)
    
    # Then save with the custom encoder as a fallback
    with open(file_path, 'w') as f:
        json.dump(cleaned_data, f, indent=indent, cls=CustomJSONEncoder)


def load_json(file_path: str) -> Any:
    """
    Load data from a JSON file.
    
    Args:
        file_path: The path to the input file.
        
    Returns:
        The loaded data.
    """
    with open(file_path, 'r') as f:
        return json.load(f) 