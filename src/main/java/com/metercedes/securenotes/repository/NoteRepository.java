package com.metercedes.securenotes.repository;
import com.metercedes.securenotes.model.Note;
import com.metercedes.securenotes.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface NoteRepository extends JpaRepository<Note, Long> {
    List<Note> findByUser(User user);
}