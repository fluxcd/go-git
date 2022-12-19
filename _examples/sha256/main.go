package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/fluxcd/go-git/v5"
	. "github.com/fluxcd/go-git/v5/_examples"
	"github.com/fluxcd/go-git/v5/plumbing/object"
)

// Basic example of how to initialise a repository using sha256 as the hashing algorithmn.
func main() {
	CheckArgs("<directory>")
	directory := os.Args[1]

	os.RemoveAll(directory)

	// Opens an already existing repository.
	r, err := git.PlainInitWithOptions(directory, &git.PlainInitOptions{ObjectFormat: git.SHA256})
	CheckIfError(err)

	w, err := r.Worktree()
	CheckIfError(err)

	// ... we need a file to commit so let's create a new file inside of the
	// worktree of the project using the go standard library.
	Info("echo \"hello world!\" > example-git-file")
	filename := filepath.Join(directory, "example-git-file")
	err = ioutil.WriteFile(filename, []byte("hello world!"), 0644)
	CheckIfError(err)

	// Adds the new file to the staging area.
	Info("git add example-git-file")
	_, err = w.Add("example-git-file")
	CheckIfError(err)

	// Commits the current staging area to the repository, with the new file
	// just created. We should provide the object.Signature of Author of the
	// commit Since version 5.0.1, we can omit the Author signature, being read
	// from the git config files.
	Info("git commit -m \"example go-git commit\"")
	commit, err := w.Commit("example go-git commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "John Doe",
			Email: "john@doe.org",
			When:  time.Now(),
		},
	})

	CheckIfError(err)

	// Prints the current HEAD to verify that all worked well.
	Info("git show -s")
	obj, err := r.CommitObject(commit)
	CheckIfError(err)

	fmt.Println(obj)
}
