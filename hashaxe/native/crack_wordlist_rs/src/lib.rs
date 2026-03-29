use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};
use std::fs::File;
use memmap2::{Mmap, MmapOptions};
use memchr::memchr_iter;
use std::io::Read;

#[pyfunction]
fn count_lines(path: &str) -> PyResult<usize> {
    let file = File::open(path)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };
    
    #[cfg(unix)]
    mmap.advise(memmap2::Advice::Sequential).unwrap_or(());

    let count = memchr_iter(b'\n', &mmap).count();
    Ok(count)
}

#[pyclass]
struct ChunkStreamer {
    mmap: Mmap,
    chunk_size: usize,
    pos: usize,
}

#[pymethods]
impl ChunkStreamer {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__<'py>(&mut self, py: Python<'py>) -> Option<Bound<'py, PyList>> {
        if self.pos >= self.mmap.len() {
            return None;
        }

        let mut lines: Vec<Bound<'py, PyBytes>> = Vec::with_capacity(self.chunk_size);
        let mut current_pos = self.pos;
        let mut lines_found = 0;

        let slice = &self.mmap[current_pos..];
        let mut iter = memchr_iter(b'\n', slice);

        while lines_found < self.chunk_size {
            if let Some(nl_idx) = iter.next() {
                let start = current_pos;
                let end = self.pos + nl_idx;
                lines.push(PyBytes::new_bound(py, &self.mmap[start..end]));
                current_pos = end + 1;
                lines_found += 1;
            } else {
                if current_pos < self.mmap.len() {
                    lines.push(PyBytes::new_bound(py, &self.mmap[current_pos..]));
                    current_pos = self.mmap.len();
                }
                break;
            }
        }

        self.pos = current_pos;
        
        if lines.is_empty() {
             None
        } else {
             Some(PyList::new_bound(py, lines))
        }
    }
}

#[pyfunction]
fn stream_chunks(path: &str, chunk_size: usize) -> PyResult<ChunkStreamer> {
    let file = File::open(path)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };
    #[cfg(unix)]
    mmap.advise(memmap2::Advice::Sequential).unwrap_or(());

    Ok(ChunkStreamer {
        mmap,
        chunk_size,
        pos: 0,
    })
}

#[pyfunction]
fn count_lines_compressed(path: &str) -> PyResult<usize> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 4];
    let n = file.read(&mut magic).unwrap_or(0);
    
    let file = File::open(path)?;
    let mut count = 0;
    
    if n >= 4 && magic == [0x04, 0x22, 0x4d, 0x18] {
        let mut decoder = lz4::Decoder::new(file)?;
        let mut buf = [0u8; 65536];
        loop {
            let bytes_read = decoder.read(&mut buf)?;
            if bytes_read == 0 { break; }
            count += memchr_iter(b'\n', &buf[..bytes_read]).count();
        }
    } else if n >= 4 && magic == [0xfd, 0x2f, 0xb5, 0x28] {
        let mut decoder = zstd::stream::Decoder::new(file)?;
        let mut buf = [0u8; 65536];
        loop {
            let bytes_read = decoder.read(&mut buf)?;
            if bytes_read == 0 { break; }
            count += memchr_iter(b'\n', &buf[..bytes_read]).count();
        }
    } else {
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        count = memchr_iter(b'\n', &mmap).count();
    }
    
    Ok(count)
}

#[pymodule]
fn hashaxe_wordlist_rs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(count_lines, m)?)?;
    m.add_function(wrap_pyfunction!(stream_chunks, m)?)?;
    m.add_function(wrap_pyfunction!(count_lines_compressed, m)?)?;
    Ok(())
}
