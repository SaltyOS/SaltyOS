// Win32 personality module — placeholder for future projection work.
//
// Core lifecycle/completion state now lives in procmgr's generic
// completion plane; Win32-specific wait objects / exit-code projection
// should layer on top of that shared source of truth rather than
// reintroducing a separate lifecycle path here.
