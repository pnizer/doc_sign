use pdf_gen::add_signed_page_to_pdf;

mod pdf_gen;

fn main() {
    // open local pdf file
    let bytes = std::fs::read("01-20233931443020.pdf").unwrap();
    let output = add_signed_page_to_pdf(bytes.as_slice());

    // write the output to a new file
    std::fs::write("output.pdf", output).unwrap();
}
