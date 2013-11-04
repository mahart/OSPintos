#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
 
 
static int sys_halt (void);
static int sys_exit (int status);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static int sys_create (const char *ufile, unsigned initial_size);
static int sys_remove (const char *ufile);
static int sys_open (const char *ufile);
static int sys_filesize (int handle);
static int sys_read (int handle, void *udst_, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static int sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static int sys_close (int handle);
 
static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);
 
/* Serializes file system operations. */
static struct lock fs_lock;
 
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}
 
/* System call handler. */

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  typedef int syscall_function (int,int,int);
  struct syscall
  {
    size_t arg_cnt;
    syscall_function *func;
  };

  static const struct syscall syscall_table[] =
  {
    {0,(syscall_function *) sys_halt},
    {1,(syscall_function *) sys_exit},
    {1,(syscall_function *) sys_exec},
    {1,(syscall_function *) sys_wait},
    {2,(syscall_function *) sys_create},
    {1,(syscall_function *) sys_remove},
    {1,(syscall_function *) sys_open},
    {1,(syscall_function *) sys_filesize},
    {3,(syscall_function *) sys_read},
    {3,(syscall_function *) sys_write},
    {2,(syscall_function *) sys_seek},
    {1,(syscall_function *) sys_tell},
    {1,(syscall_function *) sys_close}
  };

  const struct syscall *sc;
  unsigned call_nr;
  int args[3];
  copy_in(&call_nr, f->esp,sizeof call_nr);
  if(call_nr >= sizeof syscall_table/sizeof *syscall_table)
  {
    thread_exit();
  }
  sc = syscall_table+call_nr;
  ASSERT(sc->arg_cnt <= sizeof args/sizeof *args);
  memset(args, 0, sizeof args);
  copy_in(args, (uint32_t *) f->esp+1, sizeof *args * sc->arg_cnt);

  f->eax = sc->func (args[0],args[1],args[2]);
}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr) 
{
  return (uaddr < PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}
 
/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}
 
/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;
	if(!verify_user(usrc)|| usrc==NULL )
	{
		thread_exit();
        } 
  for (; size > 0; size--, dst++, usrc++) 
  {
	
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) 
      thread_exit ();
  }
}
 
/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
  if(!verify_user(us) || !us)
  {
	thread_exit();
  }

  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();
   
  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
        {
          palloc_free_page (ks);
          thread_exit (); 
        }
      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}
 
/* Halt system call. */
static int
sys_halt (void)
{
  shutdown_power_off ();
}
 /* A file descriptor, for binding a file handle to a file. */
struct file_descriptor
  {
    struct list_elem elem;      /* List element. */
    struct file *file;          /* File. */
    int handle;                 /* File handle. */
  };

/* Exit system call. */
static int
sys_exit (int exit_code) 
{
  struct thread* t = thread_current();
  struct file_descriptor *fd;

  while(!list_empty(&t->fds))
  {
	fd = list_entry(list_begin(&t->fds), struct file_descriptor, elem);
	sys_close(fd->handle);
  }
  
  t->wait_status->exit_code = exit_code;
  thread_exit ();
  return -1;
}
 
/* Exec system call. */
static int
sys_exec (const char *ufile) 
{
  int result;
  if(!ufile )/*null pointer*/
  {
	return -1;
  }
  if(!verify_user(ufile))
  {
     return -1;
   }
  lock_acquire(&fs_lock);
  result = process_execute(ufile);
  lock_release(&fs_lock);
  return result;
}
 
/* Wait system call. */
static int
sys_wait (tid_t child) 
{
	return process_wait(child);
}
 
/* Create system call. */
static int
sys_create (const char *ufile, unsigned initial_size) 
{
  int result;
  if(!ufile || !verify_user(ufile))
    return sys_exit(-1);

  result = filesys_create(ufile,initial_size);
  return result;
}
 
/* Remove system call. */
static int
sys_remove (const char *ufile) 
{
	int result;
	if(!ufile)
	{
		return false;
	}
	if(!verify_user(ufile))
	{
		sys_exit(-1);
	}
   	result =filesys_remove(ufile);
	return result;
}
 

 
/* Open system call. */
static int
sys_open (const char *ufile) 
{
  if(!ufile){
    return -1;
  }
  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd;
  struct file* f;
  int handle = -1;
  struct thread *cur = thread_current ();


 if(verify_user(kfile))
  {
    sys_exit(-1);
  }
  fd = (struct file_descriptor *)malloc (sizeof (struct file_descriptor));
  if (fd != NULL)
    {
      fd->file = filesys_open (kfile);
      if (fd->file != NULL)
        {
          handle = fd->handle = cur->next_handle++;
          list_push_front (&cur->fds, &fd->elem);
        }
      else 
	{
		free(fd);
		return -1;
	}
    }
  palloc_free_page (kfile);
  return handle;
}
 
/* Returns the file descriptor associated with the given handle.
   Terminates the process if HANDLE is not associated with an
   open file. */
static struct file_descriptor *
lookup_fd (int handle)
{
/* Add code to lookup file descriptor in the current thread's fds */
  struct list files =   thread_current()->fds;
  struct list_elem *e;
  if(handle < 1 || handle > thread_current()->next_handle)
	return NULL;
  if(handle == STDOUT_FILENO || handle == STDIN_FILENO)
	return NULL;
  
  for(e = list_begin(&files); e!=list_end(&files); e = e->next)
  {
     struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);

	if(fd!=NULL && fd->handle == handle)
        {
		return fd;
        }
  }
  
  return NULL;
}
 
/* Filesize system call. */
static int
sys_filesize (int handle) 
{
  struct file_descriptor *fd = lookup_fd(handle);
  off_t length;
  length = file_length(fd->file);
  return length;
}
 
/* Read system call. */
static int
sys_read (int handle, void *udst_, unsigned size) 
{
	
 if(!verify_user(udst_) || !udst_)
 {
   thread_exit();
 }
  struct file_descriptor *fd = lookup_fd(handle);
  int result = -1;
  if(fd!=NULL)
  {
	lock_acquire(&fs_lock);
	struct file *f = fd->file;
	result = file_read(f,udst_,size);
	lock_release(&fs_lock);
  }
	
  return result;
}
 
/* Write system call. */
static int
sys_write (int handle, void *usrc_, unsigned size) 
{
  uint8_t *usrc = usrc_;
  struct file_descriptor *fd;
  int bytes_written = 0;
  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO)
    fd = lookup_fd (handle);
  lock_acquire (&fs_lock);
  while (size > 0) 
    {
      /* How much bytes to write to this page? */
      size_t page_left = PGSIZE - pg_ofs (usrc);
      size_t write_amt = size < page_left ? size : page_left;
      off_t retval;


      /* Check that we can touch this user page. */
      if (!verify_user (usrc)) 
        {
          lock_release (&fs_lock);
          sys_exit (-1);
        }

      /* Do the write. */
      if (handle == STDOUT_FILENO)
        {
          putbuf (usrc, write_amt);
          retval = write_amt;
        }
      else if(handle == STDIN_FILENO){
          lock_release(&fs_lock);
	  return -1;
      }
      else if(!fd){
	lock_release(&fs_lock);
	return -1;
	}
      else
        retval = file_write (fd->file, usrc, write_amt);
      if (retval < 0) 
        {
          if (bytes_written == 0)
            bytes_written = -1;
          break;
        }
      bytes_written += retval;

      /* If it was a short write we're done. */
      if (retval != (off_t) write_amt)
        break;

      /* Advance. */
      usrc += retval;
      size -= retval;
    }
  lock_release (&fs_lock);
 
  return bytes_written;
}
 
/* Seek system call. */
static int
sys_seek (int handle, unsigned position) 
{
  struct file_descriptor *fd = lookup_fd(handle);
  if(!fd)
  {
    return -1;
   }
  file_seek(fd->file,position);
  return 0;
}
 
/* Tell system call. */
static int
sys_tell (int handle) 
{
  struct file_descriptor *fd = lookup_fd(handle);
  if(!fd)
  {
    return -1;
  }
  file_tell(fd->file);
  return 0;
}
 
/* Close system call. */
static int
sys_close (int handle) 
{

  struct file_descriptor *fd = lookup_fd(handle);

  if(!fd)
  {
    return -1;
  }

  lock_acquire(&fs_lock);
  file_close(fd->file);
  list_remove(&fd->elem);
  free(fd);
  lock_release(&fs_lock);

  
 
  return 0;
}
 
/* On thread exit, close all open files. */
void
syscall_exit (void) 
{
  struct thread *cur;
  struct file_descriptor *fd;
  
  cur = thread_current();
  while(!list_empty(&cur->fds))
  {
	fd = list_entry(list_front(&cur->fds),struct file_descriptor, elem);
	sys_close(fd->handle);
  }
  
  return;
}


