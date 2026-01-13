"""
Parser Registry for dynamic parser discovery and instantiation.

This module provides a registry pattern for parser classes, eliminating
the need for lengthy if/elif chains in the main entry point.
"""

from typing import Dict, Type, Callable, Optional, Any, List
import logging


class ParserRegistry:
    """
    A registry for parser classes that enables dynamic parser discovery
    and instantiation based on parser chain names.

    Example usage:
        # Register a parser
        @ParserRegistry.register('dvbs2')
        class DVBS2Parser(ParserBase):
            ...

        # Or register manually
        ParserRegistry.register('ip')(IPv4Parser)

        # Get a parser class
        parser_cls = ParserRegistry.get('dvbs2')

        # List all registered parsers
        parsers = ParserRegistry.list_parsers()
    """

    _parsers: Dict[str, Type] = {}
    _descriptions: Dict[str, str] = {}

    @classmethod
    def register(cls, name: str, description: str = "") -> Callable:
        """
        Decorator to register a parser class with a given name.

        Args:
            name: The unique identifier for the parser
            description: Human-readable description of the parser

        Returns:
            Decorator function that registers the class

        Example:
            @ParserRegistry.register('dvbs2', 'DVB-S2 Base Band Frame Parser')
            class DVBS2Parser(ParserBase):
                ...
        """
        def decorator(parser_class: Type) -> Type:
            cls._parsers[name] = parser_class
            cls._descriptions[name] = description or parser_class.__doc__ or ""
            return parser_class
        return decorator

    @classmethod
    def get(cls, name: str) -> Optional[Type]:
        """
        Get a parser class by name.

        Args:
            name: The registered name of the parser

        Returns:
            The parser class, or None if not found
        """
        return cls._parsers.get(name)

    @classmethod
    def list_parsers(cls) -> List[str]:
        """
        List all registered parser names.

        Returns:
            List of registered parser names
        """
        return list(cls._parsers.keys())

    @classmethod
    def get_description(cls, name: str) -> str:
        """
        Get the description for a registered parser.

        Args:
            name: The registered name of the parser

        Returns:
            The parser's description string
        """
        return cls._descriptions.get(name, "")

    @classmethod
    def get_all_descriptions(cls) -> Dict[str, str]:
        """
        Get all parser names and their descriptions.

        Returns:
            Dictionary mapping parser names to descriptions
        """
        return cls._descriptions.copy()


class ParserChainRegistry:
    """
    Registry for parser chains (combinations of parsers).

    A parser chain represents a sequence of parsers that process data
    in order, such as 'dvbs2-gse-ip' which runs DVBS2 -> GSE -> IP.
    """

    _chains: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def register(
        cls,
        name: str,
        description: str,
        parsers: List[str],
        run_func: Callable
    ) -> None:
        """
        Register a parser chain.

        Args:
            name: Unique identifier for the chain (e.g., 'dvbs2-gse-ip')
            description: Human-readable description
            parsers: List of parser names in the chain
            run_func: Function to execute this parser chain
        """
        cls._chains[name] = {
            'description': description,
            'parsers': parsers,
            'run_func': run_func
        }

    @classmethod
    def get(cls, name: str) -> Optional[Dict[str, Any]]:
        """
        Get a parser chain configuration by name.

        Args:
            name: The registered name of the chain

        Returns:
            Dictionary with chain configuration, or None if not found
        """
        return cls._chains.get(name)

    @classmethod
    def run(cls, name: str, *args, **kwargs) -> Any:
        """
        Execute a registered parser chain.

        Args:
            name: The registered name of the chain
            *args: Arguments to pass to the run function
            **kwargs: Keyword arguments to pass to the run function

        Returns:
            Result from the run function

        Raises:
            KeyError: If the chain name is not registered
        """
        chain = cls._chains.get(name)
        if chain is None:
            raise KeyError(f"Parser chain '{name}' not found")
        return chain['run_func'](*args, **kwargs)

    @classmethod
    def list_chains(cls) -> List[str]:
        """
        List all registered chain names.

        Returns:
            List of registered chain names
        """
        return list(cls._chains.keys())

    @classmethod
    def get_all_descriptions(cls) -> Dict[str, str]:
        """
        Get all chain names and their descriptions.

        Returns:
            Dictionary mapping chain names to descriptions
        """
        return {name: info['description'] for name, info in cls._chains.items()}


def create_parser_runner_methods(runner_class):
    """
    Decorator to automatically register parser chain methods from a class.

    This scans the class for methods starting with 'run_' and registers
    them as parser chains based on their AVAILABLE_PARSERS mapping.

    Args:
        runner_class: The ParserRunner class to decorate

    Returns:
        The decorated class
    """
    for chain_name, description in runner_class.AVAILABLE_PARSERS.items():
        method_name = 'run_' + chain_name.replace('-', '_')
        if hasattr(runner_class, method_name):
            method = getattr(runner_class, method_name)
            ParserChainRegistry.register(
                name=chain_name,
                description=description,
                parsers=chain_name.split('-'),
                run_func=method
            )
    return runner_class
