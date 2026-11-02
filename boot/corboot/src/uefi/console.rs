use super::SystemTable;

pub fn write(table: &mut SystemTable, text: &str) {
    if table.con_out.is_null() {
        return;
    }
    let mut buffer = [0u16; 128];
    for chunk in text.as_bytes().chunks(buffer.len() - 1) {
        for (slot, byte) in buffer.iter_mut().zip(chunk.iter()) {
            *slot = *byte as u16;
        }
        buffer[chunk.len()] = 0;
        unsafe {
            ((*table.con_out).output_string)(table.con_out, buffer.as_ptr());
        }
    }
}
