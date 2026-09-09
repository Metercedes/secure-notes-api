package com.metercedes.securenotes.service;

import com.metercedes.securenotes.dto.NoteDto;
import com.metercedes.securenotes.model.Note;
import com.metercedes.securenotes.model.User;
import com.metercedes.securenotes.repository.NoteRepository;
import com.metercedes.securenotes.repository.UserRepository;
import java.util.List;
import java.util.NoSuchElementException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class NoteService {

    private final NoteRepository noteRepository;
    private final UserRepository userRepository;

    public NoteService(NoteRepository noteRepository, UserRepository userRepository) {
        this.noteRepository = noteRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public NoteDto create(NoteDto dto) {
        Note note = new Note(dto.title(), dto.content(), currentUser());
        return toDto(noteRepository.save(note));
    }

    @Transactional(readOnly = true)
    public List<NoteDto> listOwnedByCurrentUser() {
        return noteRepository.findByUser(currentUser()).stream().map(NoteService::toDto).toList();
    }

    @Transactional(readOnly = true)
    public NoteDto get(Long id) {
        return toDto(requireOwnedNote(id));
    }

    @Transactional
    public NoteDto replace(Long id, NoteDto dto) {
        Note note = requireOwnedNote(id);
        note.setTitle(dto.title());
        note.setContent(dto.content());
        return toDto(note);
    }

    @Transactional
    public NoteDto patch(Long id, NoteDto dto) {
        Note note = requireOwnedNote(id);
        if (dto.title() != null) {
            note.setTitle(dto.title());
        }
        if (dto.content() != null) {
            note.setContent(dto.content());
        }
        return toDto(note);
    }

    @Transactional
    public void delete(Long id) {
        noteRepository.delete(requireOwnedNote(id));
    }

    /**
     * Ownership is enforced here rather than in the controller so that every read and write path
     * shares one check. A note belonging to another user is reported as not found, so the endpoint
     * does not confirm whether an id exists.
     */
    private Note requireOwnedNote(Long id) {
        Note note = noteRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Note not found"));
        if (!note.getUser().getId().equals(currentUser().getId())) {
            throw new AccessDeniedException("Note not found");
        }
        return note;
    }

    private User currentUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new NoSuchElementException("Authenticated user no longer exists"));
    }

    private static NoteDto toDto(Note note) {
        return new NoteDto(note.getId(), note.getTitle(), note.getContent());
    }
}
