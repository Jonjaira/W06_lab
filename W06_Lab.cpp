/**
  ********************************************************************************************************************
  * Group 1: Jessica Vargas
  *          Brycen Williams
  *          Cameron Christensen
  *          Arunas Rancevas  
  * 
  ********************************************************************************************************************


  * LAB 06. SQL INJECTION MITIGATION
  * This program simulates command injection attacks (Tautology, Additional Statement, Comment Attacks, and Union 
  * Queries). This program contains a function that accepts two input parameters, in this case a user name and a
  * password and returns a SQL string similar to the one presented in the textbook. It has a collection of text cases 
  * that will demonstrate the function is vulnerable to the aforementioned attacks. A weak mitigation function and  
  * a strong mitigation function for each of these attacks were also created.
  * 
  * 
  ********************************************************************************************************************
  */






#include <iostream>
#include <vector>
#include <utility>
#include <tuple>
#include <string>
#include <cctype>
#include <map>
#include <algorithm>

typedef std::string (*queryGeneration_t)(const std::string&, const std::string&);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                               ____       _       _             _
//                              /  _ \ _ __(_) __ _(_)_ __   __ _| |
//                              | | | | '__| |/ _` | | '_ \ / _` | |
//                              | |_| | |  | | (_| | | | | | (_| | |
//                               \___/|_|  |_|\__, |_|_| |_|\__,_|_|
//                                            |___/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//This function accepts two input parameters and returns a SQL string
std::string generate_query(const std::string& username, const std::string& password) {
    return "SELECT * FROM passwordList WHERE username = '" + username + "' AND password = '" + password + "';";
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                __        __         _      __  __ _ _   _             _   _             
//                \ \      / /__  __ _| | __ |  \/  (_) |_(_) __ _  __ _| |_(_) ___  _ __  
//                 \ \ /\ / / _ \/ _` | |/ / | |\/| | | __| |/ _` |/ _` | __| |/ _ \| '_ \ 
//                  \ V  V /  __/ (_| |   <  | |  | | | |_| | (_| | (_| | |_| | (_) | | | |
//                   \_/\_/ \___|\__,_|_|\_\ |_|  |_|_|\__|_|\__, |\__,_|\__|_|\___/|_| |_|
//                                                           |___/                         
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
std::string escape_input(const std::string& input) {
    std::string escaped_input;
    for (char c : input) {
        if (c == '\'') {
            escaped_input += "''";
        } else {
            escaped_input += c;
        }
    }
    return escaped_input;
}

std::string generate_query_weak_mitigation(const std::string& username, const std::string& password) {
    std::string user = escape_input(username);
    std::string pass = escape_input(password);
    return "SELECT * FROM passwordList WHERE username = '" + user + "' AND password = '" + pass + "';";
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                  _____ _                           __  __ _ _   _             _   _             
//                 / ____| |                         |  \/  (_) | (_)           | | (_)            
//                | (___ | |_ _ __ ___  _ __   __ _  | \  / |_| |_ _  __ _  __ _| |_ _  ___  _ __  
//                 \___ \| __| '__/ _ \| '_ \ / _` | | |\/| | | __| |/ _` |/ _` | __| |/ _ \| '_ \ 
//                 __ _) | |_| | | (_) | | | | (_| | | |  | | | |_| | (_| | (_| | |_| | (_) | | | |
//                |_____/ \__|_|  \___/|_| |_|\__, | |_|  |_|_|\__|_|\__, |\__,_|\__|_|\___/|_| |_|
//                                             __/ |                  __/ |                        
//                                            |___/                  |___/                         
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/* This section provides strong mitigation through a simplified implementation of a prepared statement. It
 * provides strong mitigation against tautology attacks because it separates the SQL query structure from the data. The
 * PreparedStatement class holds a SQL query string and a map of parameters. The setParameter method is used to set the
 * value of a parameter as well as to provide some sanitization by removing (not allowing spaces), and the getQuery method
 * generates the final SQL query with all parameters replaced by their values. The escape method is used to escape single
 * quotes in the parameter values to prevent SQL injection attacks. */

class PreparedStatement {
public:
    PreparedStatement(std::string query) : m_query(std::move(query)) {}

    void setParameter(int parameterIndex, const std::string& value) {
        m_parameters[parameterIndex] = removeSpaces("'" + escape(value) + "'");
	m_parameters[parameterIndex] = removeSemiColons(m_parameters[parameterIndex]);
    }

    std::string getQuery() const {
        std::string result = m_query;
        for (const auto& pair : m_parameters) {
            const std::string placeholder = "?" + std::to_string(pair.first);
            const size_t pos = result.find(placeholder);
            if (pos != std::string::npos) {
                result.replace(pos, placeholder.length(), pair.second);
            }
        }
        return result + ";";
    }

private:
    std::string escape(const std::string& value) const {
        std::string result;
        for (char c : value) {
            if (c == '\'') {
                result += "''";
            } else {
                result += c;
            }
        }
        return result;
    }

    std::string removeSpaces(std::string str) {
        str.erase(std::remove_if(str.begin(), str.end(), ::isspace), str.end());
        return str;
    }
    std::string removeSemiColons(std::string str) {
	str.erase(remove(str.begin(), str.end(), ';'), str.end());
    	return str;
    }
    std::string m_query;
    std::map<int, std::string> m_parameters;
};

std::string generate_query_strong_mitigation(const std::string& username, const std::string& password) {
    PreparedStatement stmt("SELECT * FROM passwordList WHERE username = ?1 AND password = ?2");
    stmt.setParameter(1, username);
    stmt.setParameter(2, password);
    return stmt.getQuery();
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                     ____       _       _             _   _____         _
//                    /  _ \ _ __(_) __ _(_)_ __   __ _| | |_   _|__  ___| |_
//                    | | | | '__| |/ _` | | '_ \ / _` | |   | |/ _ \/ __| __|
//                    | |_| | |  | | (_| | | | | | (_| | |   | |  __/\__ \ |_
//                     \___/|_|  |_|\__, |_|_| |_|\__,_|_|   |_|\___||___/\__|
//                                  |___/
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//This function executes the test cases to prove that the generate_query function is working properly
void test_query_generation() {
    std::vector<std::tuple<std::string, std::string, std::string>> testCases = {
            {"testuser", "testpass", "SELECT * FROM passwordList WHERE username = 'testuser' AND password = 'testpass'"},
            {"", "", "SELECT * FROM passwordList WHERE username = '' AND password = ''"},
            {"test_user", "test_pass", "SELECT * FROM passwordList WHERE username = 'test_user' AND password = 'test_pass'"},
            {"testuser123", "testpass123", "SELECT * FROM passwordList WHERE username = 'testuser123' AND password = 'testpass123'"},
            {std::string(100, 'a'), std::string(100, 'a'), "SELECT * FROM passwordList WHERE username = '" + std::string(500, 'a') + "' AND password = '" + std::string(500, 'a') + "'"}
        };

    for (const auto& testCase : testCases) {
        std::string query = generate_query(std::get<0>(testCase), std::get<1>(testCase));

        std::cout << "Username: \e[93m" << std::get<0>(testCase) << "\e[0m, Password: \e[93m" << std::get<1>(testCase) << "\e[0m\n";
        std::cout << "Generated Query: \e[96m" << query << "\e[0m\n\n";
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                        _   _   _             _      _____         _
//                                       / \ | |_| |_ __ _  ___| | __ |_   _|__  ___| |_
//                                      / _ \| __| __/ _` |/ __| |/ /   | |/ _ \/ __| __|
//                                     / ___ \ |_| || (_| | (__|   <    | |  __/\__ \ |_
//                                    /_/   \_\__|\__\__,_|\___|_|\_\   |_|\___||___/\__|
//
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void test_attacks(queryGeneration_t queryGenerationFunction) {
    std::vector<std::pair<std::string, std::string>> test_cases = {
        // T a u t o l o g y   T e s t   C a s e s
        {"admin' -- ", "any_password"},
        {"admin' OR '1'='1", "any_password"},
        {"admin' OR 'a'='a", "any_password"},
        {"' OR '1'='1' -- ", "any_password"},
        {"' OR 'a'='a' -- ", "any_password"},

        // A d d i t i o n a l   S t a t e m e n t   T e s t   C a s e s
        {"username", "nothing'; INSERT INTO passwordList (name, passwd) VALUES 'Bob', '1234'"},
        {"username", "nothing'; SELECT username, password from users"},
        {"username", "nothing'; DROP TABLE users"},
        {"username", "nothing'; TRUNCATE TABLE users"},
        // C o m m e n t   A t t a c k s   T e s t   C a s e s

        // U n i o n   Q u  e r i e s   T e s t   C a s e s
    };

    for (auto& test_case : test_cases) {
        std::string query = queryGenerationFunction(test_case.first, test_case.second);
        std::cout << "Username: \e[93m" << test_case.first << "\e[0m, Password: \e[93m" << test_case.second << "\e[0m\n";
        std::cout << "Generated Query: \e[96m" << query << "\e[0m\n\n";
    }
}

int main() {
    while (true) {
        std::cout << "\nMenu:\n";
        std::cout << "1. Run original function test cases\n";
        std::cout << "2. Run attack test cases on original\n";
        std::cout << "3. Run attack test cases on weak mitigated\n";
        std::cout << "4. Run attack test cases on strong mitigated\n";
        std::cout << "5. Exit\n";
        std::cout << "Enter your choice: ";
        int choice;
        std::cin >> choice;

        std::cout << "\n\n";

        switch(choice) {
            case 1: {
                test_query_generation();
                break;
            }
            case 2: {
                test_attacks(generate_query);
                break;
            }
            case 3: {
                test_attacks(generate_query_weak_mitigation);
                break;
            }
            case 4: {
                test_attacks(generate_query_strong_mitigation);
                break;
            }
            default:
                return 0;
        }
    }

    return 0;
}
