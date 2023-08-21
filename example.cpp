#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <variant>
#include <vector>
#include "hpws.hpp"


    #define PRINT_HPWS_ERROR(obj)\
    {\
        if (std::holds_alternative<hpws::error>(obj)) {\
            hpws::error e = std::get<hpws::error>(obj);\
            fprintf(stderr, "[EXAMPLE.CPP] error code: %d -- error msg: %.*s\n",\
                    e.first, (int)(e.second.size()), e.second.data());\
        } else printf("asked to print an error but the object was not an error object\n");\
    }

int example_server();
int example_client();

int main(int argc, char** argv) {

    // Become a sub-reaper so we can gracefully reap hpws child processes via hpws.hpp.
    // (Otherwise they will get reaped by OS init process and we'll end up with race conditions with gracefull kills)
    prctl(PR_SET_CHILD_SUBREAPER, 1);

    if (argc > 1 && argv[1][0] == 'c')
        return example_client();
    else
        return example_server();
}

int example_client() {
    auto accept_result = hpws::client::connect ( "hpws", 16*1024*1024, "localhost", 8080, "/", "visa_data", {} );
    
    if (std::holds_alternative<hpws::client>(accept_result)) {
        printf("[EXAMPLE.CPP] a client connected\n");
    } else {
        PRINT_HPWS_ERROR(accept_result);
        return 1;
    }

    auto client = std::move(std::get<hpws::client>(accept_result));

    {
        int msgcounter = 0;
        fprintf(stderr, "[EXAMPLE.CPP] sending message\n");
        //client.write("a message from the client\n");
        
        for(;;) {

            auto read_result = client.read();
            if ( std::holds_alternative<hpws::error>(read_result) ) {
                PRINT_HPWS_ERROR(read_result);
                return 1;
            }

            std::string_view s = std::get<std::string_view>(read_result);
            
            fprintf(stderr, "[EXAMPLE.CPP] got message from hpws: `%.*s`\n", (int)s.size(), s.data());
            fprintf(stderr, "[EXAMPLE.CPP] buf contained: `");
            for (int i = 0; i < s.size(); ++i)
               putc(s[i], stderr);
            fprintf(stderr,"`\n");           

            client.ack(s);    
            char out[1024];
            sprintf(out, "message from client: %d\n", ++msgcounter);
            client.write(out);
        }
    }
}


int example_server() {
    auto server = hpws::server::create ( "hpws", 16*1024*1024, 8080, 512, 2, "cert.pem", "key.pem", "visa_data", {} );

    if ( std::holds_alternative<hpws::server>(server) ) {
        fprintf(stderr, "[EXAMPLE.CPP] we got a server\n");

        while (1) {
            auto accept_result = std::get<hpws::server>(server).accept();

            if (std::holds_alternative<hpws::client>(accept_result)) {
                fprintf(stderr, "[EXAMPLE.CPP] a client connected\n");
            } else {
                PRINT_HPWS_ERROR(accept_result);
                continue;
            }

            auto client = std::get<hpws::client>(std::move(accept_result));
            int counter = 0;
            client.write("server to client msg1\n");
            for(;;) {
                auto read_result = client.read();
                if ( std::holds_alternative<hpws::error>(read_result) ) {
                    fprintf(stderr, "accept loop error\n");
                    PRINT_HPWS_ERROR(read_result);
                    //return 1;
                    break;
                }

                std::string_view s = std::get<std::string_view>(read_result);
                
                //printf("got message from hpws: `%.*s`\n", s.size(), s.data());
//                fprintf(stderr, "[EXAMPLE.CPP] %.*s", (int)s.size(), s.data());
                fprintf(stderr, "[EXAMPLE.CPP] got message size: %d\n", (int)s.size());
                if (s.size() <= 40)
                    fprintf(stderr, "[EXAMPLE.CPP] contained: `%.*s`\n", (int)s.size(), s.data()); 
                else
                {
                    fprintf(stderr, "[EXAMPLE.CPP] contained: `");
                    for (int i = 0; i < 20; ++i)
                        putc(s[i], stderr);
                    fprintf(stderr,"`\n");
                    fprintf(stderr, "`...`");
                    for (int i = (int)s.size() - 20; i < s.size(); ++i)
                        putc(s[i], stderr);
                    fprintf(stderr, "`\n");
                }
                client.ack(s);    

                char out[1024];
                sprintf(out, "message from server: %d\n", ++counter);
                client.write(out);

            }
        }

    } else if ( std::holds_alternative<hpws::error>(server) )  {
        fprintf(stderr, "[EXAMPLE.CPP] we got an error\n");
        PRINT_HPWS_ERROR(server);
    } else {
        fprintf(stderr, "[EXAMPLE.CPP] we got a donkey\n");
    }

    return 0;
}
