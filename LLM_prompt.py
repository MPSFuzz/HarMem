CODE_GENERATE_PROMPT = """
        you are an expert in fuzzing, please write a fuzz harness that could trigger the target function named "%s" in an open source library called "libxml2". \
        Here is some data about the libxm2 library to help you complete the harness generation: \
        1. this page is the reference of the libxml2 library: http://xmlsoft.org/html/ \
        2. this is a call chain that include the target function: %s \
        3. this target function is declared or used in %s in libxml2 source code. \
        These information may be helpful when you generate the fuzz harness. \
        The harness you gernerate should include the libxml2 library and complie successfully. \
        
        Format requirements : The code should follow the C or C++ code specification, and the program code should be complete and properly formatted.
        In the code, you should write a long sentence without using line breaks, avoiding the newline character \ n.
        Try not to use 'printf' in generated code. Don’t make up APIs that don't exist.

        Here is a template function that you can refer to its format, but you don't have to follow it strictly. \
        
        #include <stdio.h>
        #include <stdlib.h>
        #include <libxml/parser.h>
        #include <libxml/tree.h>

        /* Encoding Conversion Layer (Platform-dependent implementation) */
        xmlChar* encode_to_utf8(const char* input) {
            // Windows example: Use iconv for GBK->UTF-8 conversion
            // Linux example: Utilize built-in encoding conversion APIs
            return BAD_CAST input; // Replace with actual conversion logic
        }

        int main() {
            /* Initialization System */
            xmlInitParser();
            LIBXML_TEST_VERSION
            
            /* Document Container Declaration */
            xmlDocPtr doc = NULL;
            xmlNodePtr root_node = NULL;

            /* Main Operations Section */
            // Branch 1: Create new document
            doc = xmlNewDoc(BAD_CAST "1.0");
            root_node = xmlNewNode(NULL, encode_to_utf8("root_node"));
            xmlDocSetRootElement(doc, root_node);

            // Branch 2: Parse existing document
            // doc = xmlReadFile("input.xml", NULL, XML_PARSE_NOBLANKS)
            
            /* Node Operation Template */
            if(root_node) {
                // Text node construction
                xmlNewTextChild(root_node, NULL, 
                            encode_to_utf8("child_node"), 
                            encode_to_utf8("node_content"));
                
                // Attribute operation template
                xmlNewProp(root_node, 
                        encode_to_utf8("attribute_name"), 
                        encode_to_utf8("attribute_value"));
            }

            /* Persistence Module */
            if(doc) {
                xmlSaveFormatFileEnc("output.xml", doc, "UTF-8", 1); // Universal encoding storage
                // Chinese environment option: xmlSaveFormatFileEnc("cn.xml", doc, "GB2312", 1)
            }

            /* Error Handling Stub */
            if(!doc) {
                fprintf(stderr, "Document initialization failed");
                goto cleanup;
            }

        cleanup:
            /* Resource Cleanup Stack */
            if(doc) xmlFreeDoc(doc);
            xmlCleanupParser();
            return EXIT_SUCCESS;
        }

        When you finish the code generation, please give me the compile command. In the compile command you give, use a.c to refer to the code, and a.out to execution file,\
        and make sure the compile command can compile the code successfully. \
        
        Your answer needs to be in json format containing two properties: code and compile_command. 
        """

HARNESS_FIX = """
        You are a code repair expert. \
        The code I give you had encountered some problems during compilation. \
        The code that encountered the problem is as follows: \
        %s \
        The compile command last time you give me that I use to compile the code is as follows: \
        %s \
        The error message is: \
        %s \
        
        Now you need to modify the code or compile command I gave you to fix the problem it encountered. \
        
        If there is a problem such as "No such file or directory" in the compilation error caused by the relevant library not being found, \
        give priority to using tools such as pkg-config to repair the compilation command
        
        When you finish the code or compile command modification, please give me the result. \
        In the compile command you give, use a.c to refer to the code, and a.out to execution file,\
        and make sure the compile command can compile the code successfully. \
        
        Your answer needs to be in json format containing two properties: code and compile_command. \
"""