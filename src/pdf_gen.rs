use js_sys::wasm_bindgen;
use lopdf::{content::{Content, Operation}, dictionary, Document, Object, Stream};

pub fn add_signed_page_to_pdf(bytes: &[u8]) -> Vec<u8> {
    // Parse the input bytes into a PDF document
    let mut doc = Document::load_from(bytes).unwrap();

    // Get the pages id from a PDF document, the root element of the tree
    let catalog = doc.catalog().unwrap();
   

    // get Pages from catalog    
    let pages_id = catalog.get(b"Pages").unwrap().as_reference().unwrap();
    let mut pages_obj = doc.get_object(pages_id).unwrap().as_dict().unwrap().clone();


    // Create a new page with the text "Documento assinado digitalmente"
    // BT /F1 24 Tf 100 100 Td (Documento assinado digitalmente) Tj ET
    let content = Content {
        operations: vec![
             // BT begins a text element. it takes no operands
            Operation::new("BT", vec![]),
            // Tf specifies the font and font size. Font scaling is complicated in PDFs. Reference
            // the reference for more info.
            // The into() methods are defined based on their paired .from() methods (this
            // functionality is built into rust), and are converting the provided values into
            // An enum that represents the basic object types in PDF documents.
            Operation::new("Tf", vec!["F1".into(), 24.into()]),
            // Td adjusts the translation components of the text matrix. When used for the first
            // time after BT, it sets the initial text position on the page.
            // Note: PDF documents have Y=0 at the bottom. Thus 600 to print text near the top.
            Operation::new("Td", vec![100.into(), 100.into()]),
            // Tj prints a string literal to the page. By default, this is black text that is
            // filled in. There are other operators that can produce various textual effects and
            // colors
            Operation::new("Tj", vec![Object::string_literal("Documento assinado digitalmente")]),
            // ET ends the text element
            Operation::new("ET", vec![]),
        ]
    };
    
    // Create the content stream and add it to the document
    let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
    
    // Create a new font and resources dictionary
    let font_id = doc.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Courier",
    });
    let resources_id = doc.add_object(dictionary! {
        "Font" => dictionary! {
            "F1" => font_id,
        },
    });

    // Create a new page dictionary
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content_id,
        "Resources" => resources_id        
    });
    

    // Update pages object with new page
    let mut kids = pages_obj.get(b"Kids").unwrap().as_array().unwrap().clone();
    kids.push(Object::Reference(page_id));
    pages_obj.set("Count",  kids.len() as u32);
    pages_obj.set("Kids", kids);

    // update document pages with dictionary
    doc.objects.insert(pages_id, Object::Dictionary(pages_obj));        
    
    // Serialize the modified PDF document into a new Vec of bytes
    let mut output = Vec::new();
    doc.save_to(&mut output).unwrap();

    output
}
