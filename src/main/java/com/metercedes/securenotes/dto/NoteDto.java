package com.metercedes.securenotes.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record NoteDto(
        Long id,
        @NotBlank(message = "Title is required") @Size(max = 200) String title,
        @Size(max = 10_000) String content) {
}
