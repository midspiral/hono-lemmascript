/**
 * @module
 * FilePath utility.
 */

//@ declare-type FilePathOptionsCore { filename: string, root: string | undefined }

type FilePathOptions = {
  filename: string
  root?: string
  defaultDocument?: string
}

export const getFilePath = (options: FilePathOptions): string | undefined => {
  let filename = options.filename
  const defaultDocument = options.defaultDocument || 'index.html'

  if (filename.endsWith('/')) {
    // /top/ => /top/index.html
    filename = filename.concat(defaultDocument)
  } else if (!filename.match(/\.[a-zA-Z0-9_-]+$/)) {
    // /top => /top/index.html
    filename = filename.concat('/' + defaultDocument)
  }

  const path = getFilePathWithoutDefaultDocument({
    root: options.root,
    filename,
  })

  return path
}

export const getFilePathWithoutDefaultDocument = (
  options: Omit<FilePathOptions, 'defaultDocument'>
): string | undefined => {
  //@ verify
  //@ type options FilePathOptionsCore
  //@ ensures implies($result !== undefined, !ContainsParentDir(options.filename))
  let root = options.root || ''
  let filename = options.filename

  // Security check: reject any `..` path segment in the input.
  //@ havoc
  const hasParentDir = /(?:^|[\/\\])\.\.(?:$|[\/\\])/.test(filename)
  //@ assume hasParentDir === ContainsParentDir(filename)
  if (hasParentDir) {
    return
  }

  // /foo.html => foo.html
  //@ havoc
  filename = filename.replace(/^\.?[\/\\]/, '')

  // foo\bar.txt => foo/bar.txt
  //@ havoc
  filename = filename.replace(/\\/g, '/')

  // assets/ => assets
  //@ havoc
  root = root.replace(/\/$/, '')

  // ./assets/foo.html => assets/foo.html
  let path = root ? root + '/' + filename : filename
  //@ havoc
  path = path.replace(/^\.?\//, '')

  //@ skip
  if (root[0] !== '/' && path[0] === '/') {
    return
  }

  return path
}
