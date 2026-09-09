package com.metercedes.securenotes.controller;

import com.metercedes.securenotes.dto.NoteDto;
import com.metercedes.securenotes.service.NoteService;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/notes")
public class NoteController {

    private final NoteService noteService;

    public NoteController(NoteService noteService) {
        this.noteService = noteService;
    }

    @PostMapping
    public ResponseEntity<NoteDto> create(@Valid @RequestBody NoteDto dto) {
        NoteDto created = noteService.create(dto);
        return ResponseEntity.created(URI.create("/api/notes/" + created.id())).body(created);
    }

    @GetMapping
    public List<NoteDto> list() {
        return noteService.listOwnedByCurrentUser();
    }

    @GetMapping("/{id}")
    public NoteDto get(@PathVariable Long id) {
        return noteService.get(id);
    }

    @PutMapping("/{id}")
    public NoteDto replace(@PathVariable Long id, @Valid @RequestBody NoteDto dto) {
        return noteService.replace(id, dto);
    }

    @PatchMapping("/{id}")
    public NoteDto patch(@PathVariable Long id, @RequestBody NoteDto dto) {
        return noteService.patch(id, dto);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        noteService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
