"""Text tokenization for semantic chunking."""


class Tokenizer:
    """Tokenizes text and provides context extraction."""

    def get_context_window(self, text: str, start: int, end: int, window_size: int = 30) -> str:
        """Extract context window around a match."""
        context_start = max(0, start - window_size)
        context_end = min(len(text), end + window_size)
        context = text[context_start:context_end].strip()
        context = ' '.join(context.split())
        if len(context) > 60:
            context = context[:60] + "..."
        return context
