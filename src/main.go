/*
 * ACTIVE FTP SERVER Start-up Code (WinSock 2) simple rewrite on Rust
 *
 * This code gives parts of the answers away.
 * The sample TCP server codes will help you accomplish this.
 *
 * OVERVIEW
 * Only the active FTP mode connection is implemented (watch out for firewall
 * issues - do not block your own FTP server!).
 *
 * Only IP4
 *
 * The ftp LIST command is fully implemented, in a very naive way using
 * redirection and a temporary file.
 */
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var MONTHS = [...]string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

const SYSTEM_COMMAND_DEL = "del"
const SYSTEM_COMMAND_MKDIR = "mkdir"
const SYSTEM_COMMAND_RMDIR = "rmdir"
const SYSTEM_COMMAND_RENAME = "rename"

var SHOW_DEBUG_MESSAGE chan bool = false
var CONVERT_CYRILLIC chan bool = false

const DEFAULT_PORT = "21"
const BIG_BUFFER_SIZE uint = 65535

// Arguments:
//
//	0:  Program name
//	1:  Port number
//	2:  Debug mode (true/false)
//	3:  Use convert cyrillic file and directory name between Android and Windows 7 (true/false)
func main() int {
	//var argc = len(os.Args)
	//var argv: Vec<String> = std::env::args().collect();

	set_debug(debug_mode())

	set_convert_cyrillic(convert_cyrillic())

	/*if env::var("TEMP").is_err() {
	      if is_debug() {
	          writeln!(io::stdout(), "Error, not find environment <TEMP>!!")?;
	      }
	      return Err(io::Error::new(io::ErrorKind::Other, "TEMP not found"));
	  } else {
	      if var Ok(temp) = env::var("TEMP") {
	          if temp.len() > 50 {
	              if is_debug() {
	                  writeln!(io::stdout(), "Error, very long size for environment <TEMP>!!")?;
	              }
	              return Err(io::Error::new(io::ErrorKind::Other, "TEMP too long"));
	          }
	      }
	  }
	*/
	var result = get_server_address_info()
	if len(result) == 0 {
		return 1
	}
	/*
	   var listener = TcpListener::bind(result.unwrap()).unwrap();
	*/
	show_server_info()
	/*
	   server_listen(listener)
	*/
	return 0
}

func set_debug(b bool) {
	SHOW_DEBUG_MESSAGE = b
}

func is_debug() bool {
	return SHOW_DEBUG_MESSAGE
}

// Returns true if user indicated that debug mode should be on.
func debug_mode() bool {
	if len(os.Args) > 2 {
		if os.Args[2] == "true" {
			return true
		}
	}

	return false
}

func set_convert_cyrillic(b bool) {
	CONVERT_CYRILLIC = b
}

func is_convert_cyrillic() bool {
	return CONVERT_CYRILLIC
}

// Returns true if user indicated that convert cyrillic should be on.
func convert_cyrillic() bool {
	if len(os.Args) > 3 {
		if os.Args[3] == "true" {
			return true
		}
	}

	return false
}

func show_server_info() {
	fmt.Println("===============================")
	fmt.Println("     159.334 FTP Server        ")
	fmt.Println("===============================")
}

// Gets the servers address information based on arguments.
func get_server_address_info() /*Result<SocketAddr, i32>*/ {
	var addr string
	if len(os.Args) > 1 {
		//format!("0.0.0.0:{}", os.Args[1])
	} else {
		//format!("0.0.0.0:{}", DEFAULT_PORT)
	}
	/*
	   var socket_addr = addr.to_socket_addrs()

	   	.map_err(|_| 3)?
	   	.next()
	   	.ok_or(3)?;

	   	if is_debug() {
	   	    fmt.Println("<<<DEBUG INFO>>>: Server address information created.");
	   	}

	   Ok(socket_addr)
	*/
}

// Listen for client communication and deal with it accordingly.
func server_listen(listener TcpListener) {
	/*
	   for stream in listener.incoming() {
	       match stream {
	           Ok(s) => {
	               thread::spawn(move || handle_clients(s));
	           },
	           Err(e) => panic!("Error listening for connections: {}", e),
	       }
	   }

	   fmt.Println("SERVER SHUTTING DOWN...");

	   Ok(())
	*/
}

// Accepts new clients and deals with commands.
func handle_clients(s TcpStream) {
	show_client_info(&s)

	if !send_message(&s, "220 FTP Server ready.\r\n") {
		close_client_connection(&s)
		return
	}

	var success = true
	var authroised_login = false
	var connect_to string
	var client_id = 1 //s.peer_addr().unwrap().port();
	var current_directory string
	var name_file_or_dir_for_rename = string

	for success {
		success = communicate_with_client(
			s,
			connect_to,
			authroised_login,
			client_id,
			current_directory,
			name_file_or_dir_for_rename)
	}

	close_client_connection(&s)
}

// Takes incoming connection and assigns new socket.
func show_client_info(s TcpStream) {
	fmt.Println("A client has been accepted.")

	var client_host = &s.peer_addr().unwrap().ip().to_string()
	var client_service = &s.peer_addr().unwrap().port().to_string()

	fmt.Print("Connected to client with IP address: {}", client_host)
	fmt.Println(", at Port: {}", client_service)
}

// Receive and handle messages from client, returns false if client ends connection.
func communicate_with_client(s TcpStream, connect_to string, authroised_login bool, client_id u16, current_directory string, name_file_or_dir_for_rename string) bool {
	var receive_buffer []byte
	var user_name string
	var password string

	var receipt_successful = receive_message(s, receive_buffer)
	if !receipt_successful {
		return receipt_successful
	}

	var success bool

	var maybe_command string = receive_buffer[:4]

	switch maybe_command {
	case "USER":
		{
			var i_attempts = 0

			for {
				success = command_user_name(s, receive_buffer, user_name, authroised_login)

				if !success {
					i_attempts++

					receipt_successful = receive_message(s, receive_buffer)
					if !receipt_successful {
						return receipt_successful
					}
				}
				if success || i_attempts >= 3 {
					break
				}
			}
			return success
		}

	case "PASS":
		command_password(s, receive_buffer, password, *authroised_login)
	case "SYST":
		command_system_information(s)
	case "QUIT":
		command_quit()
	case "PORT":
		command_port(s, connect_to, receive_buffer)
	case "LIST", "NLST":
		command_list(s, connect_to, client_id, current_directory)
	case "RETR":
		command_retrieve(s, connect_to, receive_buffer, current_directory)
	case "STOR":
		command_store(s, connect_to, receive_buffer, current_directory)
	case "CWD ":
		command_change_working_directory(s, receive_buffer, current_directory)
	case "DELE":
		command_delete(s, receive_buffer)
	case "MKD ":
		command_make_directory(s, receive_buffer)
	case "RMD ":
		command_delete_directory(s, receive_buffer)
	case "TYPE":
		command_type(s, receive_buffer)
	case "FEAT":
		command_feat(s)
	case "OPTS":
		command_opts(s, receive_buffer)
	case "RNFR":
		command_rename_from(s, receive_buffer, name_file_or_dir_for_rename)
	case "RNTO":
		command_rename_to(s, receive_buffer, name_file_or_dir_for_rename)
	case "MFMT":
		command_mfmt(s, receive_buffer)
	default:
		command_unknown(s)
	}

	return success
}

// Receives message and saves it in receive buffer, returns false if connection ended.
func receive_message(s TcpStream, receive_buffer []byte) bool {
	var bytes int
	var buffer []byte

	for {
		bytes = s.read(buffer)

		if bytes == 0 {
			break
		}

		receive_buffer.push(buffer[0])

		if buffer[0] == '\n' {
			receive_buffer.pop()
			break
		} else if buffer[0] == '\r' {
			receive_buffer.pop()
		}
	}

	if bytes == 0 {
		return false
	}

	if is_debug() {
		fmt.Printf("<--- &v", receive_buffer)
	}

	true
}

// Client sent USER command, returns false if fails.
func command_user_name(s TcpStream, receive_buffer []byte, user_name string, authroised_login bool) bool {
	remove_command(receive_buffer, user_name, 4)

	//var user_name = String::from_utf8_lossy(&user_name);

	fmt.Printf("User: \"%s\" attempting to login.", user_name)

	*authroised_login = is_valid_user_name(&user_name)

	if *authroised_login {
		fmt.Println("User name valid. Password required.")

		send_message(s, "331 Authorised login requested, please specify the password.\r\n")
	} else {
		fmt.Println("User name unauthorised. Public access only.")

		send_message(s, "331 Public login requested, please specify email as password.\r\n")
	}
}

// Send message to client, returns true if message was sended.
func send_message(s TcpStream, send_buffer string) bool {
	var bytes = len(send_buffer)
	/*bytes = s.write_all(send_buffer.as_bytes()) {
	    Ok(()) => {
	        if is_debug() {
	            print!("---> {}", send_buffer);
	        }
	    },
	    Err(_) => bytes = 0
	};*/
	return bytes == len(send_buffer)
}

// Returns true if valid user name.
func is_valid_user_name(user_name string) bool {
	return user_name == "nhreyes"
}

// Client sent PASS command, returns false if fails.
func command_password(s TcpStream, receive_buffer []byte, password string, authroised_login bool) bool {
	remove_command(receive_buffer, password, 4)

	var valid_password = is_valid_password(password, authroised_login)

	var send_buffer string

	if valid_password {
		fmt.Println("Password valid. User logged in.")

		send_buffer = "230 Login successful.\r\n"
	} else {
		fmt.Println("Password invalid. Login failed.")

		send_buffer = "530 Login authentication failed.\r\n"
	}

	if !send_message(s, send_buffer) {
		return false
	}

	valid_password
}

// Returns true if valid password.
func is_valid_password(password string, authroised_login bool) bool {
	if authroised_login {
		return password == "334"
	} else {
		return is_email_address(password)
	}
}

// Client sent SYST command, returns false if fails.
func command_system_information(s TcpStream) bool {
	fmt.Println("System information requested.")

	return send_message(s, "215 Windows Type: WIN64\r\n")
}

// Client sent QUIT command, returns false if fails.
func command_quit() bool {
	fmt.Println("Client has quit the session.")

	return false
}

// Client sent PORT command, returns false if fails.
func command_port(s TcpStream, connect_to string, receive_buffer []byte) bool {
	fmt.Println("===================================================")
	fmt.Println("\tActive FTP mode, the client is listening...")

	*connect_to = get_client_ip_and_port(receive_buffer)

	if connect_to.len() == 0 {
		send_argument_syntax_error(s)
	} else {
		send_message(s, "200 PORT Command successful.\r\n")
	}
}

// Gets the client's IP and port number for active connection.
func get_client_ip_and_port(receive_buffer []byte) string {
	var temp_string = string(receive_buffer[5:])
	var parts []string = strings.split(temp_string, ",")

	if parts.len() != 6 || !receive_buffer.starts_with("PORT ") {
		return ""
	}

	if is_debug() {
		fmt.Println("%v", parts)
	}

	var active_ip []string = parts[:4]
	//    .iter()
	//    .map(|&s| s.parse::<u8>().unwrap())
	//    .collect();

	if is_debug() {
		fmt.Println("%v", active_ip)
	}

	var active_port []string = parts[4:]
	//    .iter()
	//    .map(|&s| s.parse::<u16>().unwrap())
	//    .collect();

	if is_debug() {
		fmt.Println("%v", active_port)
	}

	var ip_buffer = fmt.Sprintf("%s.%s.%s.%s", active_ip[0], active_ip[1], active_ip[2], active_ip[3])
	fmt.Println("\tClient's IP is %v", ip_buffer)

	var port_decimal = (active_port[0] << 8) + active_port[1]
	var port_buffer = port_decimal.to_string()
	fmt.Println("\tClient's Port is {}", port_buffer)

	var result2 string
	result2 += ip_buffer.as_str()
	result2 += ":"
	result2 += port_buffer.as_str()

	return result2
}

func send_argument_syntax_error(s TcpStream) bool {
	return send_message(s, "501 Syntax error in arguments.\r\n")
}

// Sends the client a message to say data connection failed.
func send_failed_active_connection(s TcpStream) bool {
	return send_message(s, "425 Something is wrong, can't start active connection.\r\n")
}

// Client sent LIST command, returns false if fails.
func command_list(s TcpStream, connect_to string, client_id u16, current_directory string) bool {
	var path_temp = get_temp_directory()

	var tmp = fmt.Sprintf("%s\\%d_tmp_dir.txt", path_temp, client_id)

	var result = send_file(s, connect_to, tmp.as_str(), client_id, current_directory.as_str())

	/*match result {
	    Ok(_) => {},
	    Err(_) => return false
	};*/

	return send_message(s, "226 Directory send OK.\r\n")
}

func get_temp_directory() string {
	return os.Getenv("TEMP")
}

func delete_temp_files(file1, file2, file3 string) {
	execute_system_command(SYSTEM_COMMAND_DEL, file1, "")
	execute_system_command(SYSTEM_COMMAND_DEL, file2, "")
	execute_system_command(SYSTEM_COMMAND_DEL, file3, "")
}

// Sends specified file to client.
func send_file(s TcpStream, connect_to string, file_name string, client_id u16, current_directory string) /*-> Result<*/ i32 /*, std::io::Error>*/ {
	var tmp string
	var tmp_directory string
	var tmp_file string
	var tmp_dir_directory = "dir /A:D /B"
	var tmp_dir_files = "dir /A:-D /-C"

	if client_id > 0 {
		fmt.Println("Client has requested the directory listing.")
		/*
		   var now = Utc::now();
		   var (_is_common_era, year) = now.year_ce();

		   var path_temp = get_temp_directory();

		   tmp = format!("{}\\{}_tmp_dir.txt", path_temp, client_id).to_string();
		   tmp_directory = format!("{}\\{}_tmp_dir2.txt", path_temp, client_id).to_string();
		   tmp_file = format!("{}\\{}_tmp_dir3.txt", path_temp, client_id).to_string();

		   tmp_dir_directory += " >";
		   tmp_dir_directory += &tmp_directory;

		   tmp_dir_files += " >";
		   tmp_dir_files += &tmp_file;

		   if is_debug() {
		       fmt.Println("<<<DEBUG INFO>>>: {} {}", tmp_dir_files, current_directory);
		   }

		   execute_system_command(tmp_dir_files.as_str(), current_directory, "");

		   if is_debug() {
		       fmt.Println("<<<DEBUG INFO>>>: {} {}", tmp_dir_directory, current_directory);
		   }

		   execute_system_command(tmp_dir_directory.as_str(), current_directory, "");

		   var f_in_dir = File::create(tmp.as_str())?;

		   var f_in_directory = File::open(tmp_directory.as_str())?;

		   var is_first = true;

		   var buffer []byte []byte

		   for iter in f_in_directory.bytes() {
		       var byte = iter.unwrap();
		       if byte == b'\r' {
		           continue;
		       } else if byte == b'\n' {
		           var tmp_buffer_dir: String = "drw-rw-rw-    1 user       group        512 Oct 15  2024 ".to_string();
		           if !is_convert_cyrillic() {
		               var line = String::from_utf8_lossy(&buffer[0..]);
		               tmp_buffer_dir += &line;
		           } else {
		               var tmp_new_file_name []byte []byte
		               simple_conv(buffer.clone(), tmp_new_file_name, false);
		               var str_tmp_new_file_name = String::from_utf8_lossy(&tmp_new_file_name[0..]);
		               tmp_buffer_dir += &str_tmp_new_file_name;
		           }
		           if !is_first {
		               var _ = f_in_dir.write_all("\n".as_bytes());
		           } else {
		               is_first = false;
		           }
		           var _ = f_in_dir.write_all(tmp_buffer_dir.as_bytes());
		           if is_debug() {
		               fmt.Println("{}", tmp_buffer_dir);
		           }
		           buffer.clear();
		       } else {
		           buffer.push(byte);
		       }
		   }

		   var result = File::open(tmp_file.as_str());
		   var f_in_files;
		   match result {
		       Ok(f) => f_in_files = f,
		       Err(e) => panic!("{:?} '{}'", e, tmp_file)
		   }

		   var skip_lines = 5;
		   var tmp_file_name: String;
		   var tmp_buffer_file: String;

		   for iter in f_in_files.bytes() {
		       var byte = iter.unwrap();
		       if byte == b'\r' {
		           continue;
		       } else if byte == b'\n' {
		           if skip_lines > 0 {
		               skip_lines -= 1;
		               buffer.clear();
		               continue;
		           }

		           if is_numerical(buffer[0]) {
		               var line = String::from_utf8_lossy(&buffer[0..36]);

		               var v: Vec<&str> = line.split_whitespace().collect();
		               var tmp_date = v[0];

		               var i_day = (tmp_date[0..=1]).to_string().parse::<u8>().unwrap();
		               var i_month = (tmp_date[3..=4]).to_string().parse::<usize>().unwrap();
		               var i_year = (tmp_date[6..=9]).to_string().parse::<u32>().unwrap();

		               var tmp_time = v[1];
		               var i_hour = (tmp_time[0..=1]).to_string().parse::<u8>().unwrap();
		               var i_minute = (tmp_time[3..=4]).to_string().parse::<u8>().unwrap();

		               var tmp_file_size = v[2];
		               var file_size: usize = tmp_file_size.parse::<usize>().unwrap();

		               var tmp_file_name_vec []byte = (&buffer[36..]).into();

		               if year == i_year {
		                   tmp_buffer_file = format!("-rw-rw-rw-    1 user       group {:10} {} {:02} {:02}:{:02} ", file_size, MONTHS[i_month - 1], i_day, i_hour, i_minute).to_string();
		               } else {
		                   tmp_buffer_file = format!("-rw-rw-rw-    1 user       group {:10} {} {:02}  {:04} ", file_size, MONTHS[i_month - 1], i_day, i_year).to_string();
		               }
		               if !is_convert_cyrillic() {
		                   tmp_file_name = String::from_utf8_lossy(&buffer[36..]).to_string();
		                   tmp_buffer_file += &tmp_file_name;
		               } else {
		                   var tmp_new_file_name_vec []byte []byte
		                   simple_conv(tmp_file_name_vec, tmp_new_file_name_vec, false);
		                   var tmp_new_file_name = String::from_utf8_lossy(&tmp_new_file_name_vec[0..]);
		                   tmp_buffer_file += &tmp_new_file_name;
		               }
		               if !is_first {
		                   var _ = f_in_dir.write_all("\n".as_bytes());
		               } else {
		                   is_first = false;
		               }
		               var _ = f_in_dir.write_all(tmp_buffer_file.as_bytes());
		               if is_debug() {
		                   fmt.Println("{}", tmp_buffer_file);
		               }
		           }
		           buffer.clear();
		       } else {
		           buffer.push(byte);
		       }
		   }

		   var _ = f_in_dir.write_all("\n".as_bytes());
		*/
	} else {
		fmt.Printf("Client has requested to retrieve the file: \"%s\".", file_name)
	}

	var file_name_for_open string

	if client_id > 0 {
		file_name_for_open = tmp.clone()
	} else {
		file_name_for_open = current_directory.to_string()

		if file_name_for_open.len() > 0 {
			file_name_for_open += "\\"
		}

		file_name_for_open += file_name
	}

	var f_in, err = os.OpenFile(file_name_for_open, os.O_RDONLY, 0666)

	/*match result {
	  Err(_) => {*/
	if err != nil {
		fmt.Printf("The file: \"%s\" does not exist.", file_name_for_open)

		if !send_message(s, "550 File name invalid.\r\n") {
			return 0
		}

		return -1
	} /*,
	    Ok(f) => {
	        f_in = f;
	        if !send_message(s, "150 Data connection ready.\r\n") {
	            if client_id > 0 {
	                if !is_debug() {
	                    delete_temp_files(&tmp, &tmp_directory, &tmp_file);
	                }
	            }

	            return Ok(0);
	        }
	    }
	}*/

	/*var temp_buffer = [0; BIG_BUFFER_SIZE];
	  var send_to;

	  match TcpStream::connect(connect_to.as_str()) {
	      Ok(stream) => send_to = stream,
	      Err(_) => {
	          if client_id > 0 {
	              if !is_debug() {
	                  delete_temp_files(&tmp, &tmp_directory, &tmp_file);
	              }
	          }
	          return Ok(0);
	      }
	  }*/

	for {
		//var result = f_in.read(temp_buffer[..]);

		var read_bytes int
		/*
		   match result {
		       Ok(n) => read_bytes = n,
		       Err(_) => read_bytes = 0
		   }
		*/
		if read_bytes == 0 {
			break
		}
		/*
		   var bytes = match send_to.write_all(&temp_buffer[..read_bytes]) {
		       Ok(()) => read_bytes,
		       Err(_) => 0,
		   };
		*/
		if bytes != read_bytes {
			if client_id > 0 {
				if !is_debug() {
					delete_temp_files(&tmp, &tmp_directory, &tmp_file)
				}
			}
			return 0
		}
	}

	if client_id > 0 {
		if !is_debug() {
			delete_temp_files(&tmp, &tmp_directory, &tmp_file)
		}
	}

	fmt.Println("File sent successfully.")

	return 1
}

// return '0' if not have error.
func execute_system_command(command_name_with_keys, file_name_first, file_name_second string) i32 {
	//use std::os::windows::process::CommandExt;

	var cmd_args string

	var all_args []string = strings.split(command_name_with_keys, " ")
	var is_first = true
	/*for arg in all_args {
	    if is_first {
	        cmd_args = arg.to_string();
	        is_first = false;
	    } else {
	        cmd_args.push_str(" ");
	        cmd_args.push_str(arg);
	    }
	}*/

	if len(file_name_first) > 0 {
		cmd_args.push_str(" ")
		if file_name_first.contains(" ") {
			cmd_args.push_str("\"")
		}
		cmd_args.push_str(file_name_first)
		if file_name_first.contains(" ") {
			cmd_args.push_str("\"")
		}
	}

	if len(file_name_second) > 0 {
		cmd_args.push_str(" ")
		if file_name_second.contains(" ") {
			cmd_args.push_str("\"")
		}
		cmd_args.push_str(file_name_second)
		if file_name_second.contains(" ") {
			cmd_args.push_str("\"")
		}
	}

	if is_debug() {
		fmt.Println("Execute command: {}", cmd_args)
	}

	var cmd = exec.Command("cmd.exe", cmd_args)
	//        .arg("/C")
	//        .raw_arg(&format!("\"{cmd_args}\""))
	//        .status()
	//        .expect("command failed to start");
	/*
	   match status.code() {
	       Some(code) => code,
	       None => -1
	   }
	*/
	err := cmd.Run()
	if err != nil {
		return -1
	}
	return 0
}

// Client sent RETR command, returns false if fails.
func command_retrieve(s TcpStream, connect_to string, receive_buffer []byte, current_directory string) bool {
	var tmp_vec []byte

	remove_command(receive_buffer, tmp_vec, 4)

	var tmp = string(tmp_vec)

	var result = send_file(s, connect_to, tmp.as_str(), 0, current_directory.as_str())

	/*match result {
	    Ok(_) => {},
	    Err(_) => return false
	};*/

	return send_message(s, "226 File transfer complete.\r\n")
}

// Client sent STORE command, returns false if fails.
func command_store(s TcpStream, connect_to string, receive_buffer []byte, current_directory string) bool {
	var tmp_vec []byte

	remove_command(receive_buffer, tmp_vec, 4)

	var tmp = string(tmp_vec)

	var result = save_file(s, connect_to, tmp.as_str(), current_directory.as_str())

	if !result {
		return result
	}

	send_message(s, "226 File transfer complete.\r\n")
}

// Sends specified file to client.
func save_file(s TcpStream, connect_to, file_name, current_directory string) bool {
	fmt.Println("Client has requested to store the file: \"{}\".", file_name)

	var recv_from []byte

	/*match TcpStream::connect(connect_to.as_str()) {
	    Ok(stream) => recv_from = stream,
	    Err(_) => {
	        send_failed_active_connection(s);
	        return false;
	    }
	}*/

	if !send_message(s, "150 Data connection ready.\r\n") {
		return false
	}

	var file_name_full = current_directory

	if len(file_name_full) > 0 {
		file_name_full += "\\"
	}

	file_name_full += file_name

	var f_out_file, err = os.Create(file_name_full)
	/*var f_out_file;
	  match result {
	      Ok(f) => f_out_file = f,
	      Err(_) => return false
	  }*/
	if err != nil {
		return false
	}

	var temp_buffer []byte // = vec![0; BIG_BUFFER_SIZE];

	for {
		var recv_bytes = recv_from.read(temp_buffer)

		if recv_bytes > 0 {
			var _ = f_out_file.write_all(&temp_buffer[:recv_bytes])
		} else {
			break
		}
	}

	fmt.Println("File saved successfully.")

	return true
}

// Client sent CWD command, returns false if connection ended.
func command_change_working_directory(s TcpStream, receive_buffer []byte, current_directory string) bool {
	var tmp_vec []byte

	remove_command(receive_buffer, tmp_vec, 4)

	replace_backslash(tmp_vec)

	current_directory = string(tmp_vec)

	if current_directory == "\\" {
		*current_directory = "".to_string()
	}

	send_message(s, "250 Directory successfully changed.\r\n")
}

// Client sent DELETE command, returns false if connection ended.
func command_delete(s TcpStream, receive_buffer []byte) bool {
	var tmp_vec []byte

	remove_command(receive_buffer, tmp_vec, 5)

	replace_backslash(tmp_vec)

	var tmp = string(tmp_vec)

	execute_system_command(SYSTEM_COMMAND_DEL, tmp.as_str(), "")

	if is_debug() {
		fmt.Println("<<<DEBUG INFO>>>: {} {}", SYSTEM_COMMAND_DEL, tmp)
	}

	return send_message(s, "250 Requested file action okay, completed.\r\n")
}

// Client sent MKD command, returns false if connection ended.
func command_make_directory(s TcpStream, receive_buffer []byte) bool {
	var tmp_vec []byte

	remove_command(receive_buffer, tmp_vec, 4)

	replace_backslash(tmp_vec)

	var tmp = string(tmp_vec)

	execute_system_command(SYSTEM_COMMAND_MKDIR, tmp.as_str(), "")

	if is_debug() {
		fmt.Println("<<<DEBUG INFO>>>: {} {}", SYSTEM_COMMAND_MKDIR, tmp)
	}

	var send_buffer = fmt.Sprintf("257 '/%s' directory created\r\n", tmp)

	return send_message(s, &send_buffer)
}

// Client sent RMD command, returns false if connection ended.
func command_delete_directory(s TcpStream, receive_buffer []byte) bool {
	var tmp_vec []byte

	remove_command(receive_buffer, tmp_vec, 4)

	replace_backslash(tmp_vec)

	var tmp = string(tmp_vec)

	execute_system_command(SYSTEM_COMMAND_RMDIR, tmp.as_str(), "")

	if is_debug() {
		fmt.Println("<<<DEBUG INFO>>>: {} {}", SYSTEM_COMMAND_RMDIR, tmp)
	}

	return send_message(s, "250 Requested file action okay, completed.\r\n")
}

// Client sent TYPE command, returns false if connection ended.
func command_type(s TcpStream, receive_buffer []byte) bool {
	var tmp []byte

	remove_command(receive_buffer, tmp, 4)

	var type_name = string(tmp)

	var send_buffer = fmt.Sprintf("200 Type set to %s.\r\n", type_name)

	return send_message(s, &send_buffer)
}

// Client sent FEAT command, returns false if fails.
func command_feat(s TcpStream) bool {
	return send_message(s, "211-Extensions supported\r\n UTF8\r\n MFMT\r\n211 end\r\n")
}

// Client sent OPTS command, returns false if connection ended.
func command_opts(s TcpStream, receive_buffer []byte) bool {
	var tmp_vec []byte

	remove_command(receive_buffer, tmp_vec, 4)

	var opts_name = string(tmp_vec)

	if opts_name == "UTF8 ON" {
		return send_message(s, "200 UTF8 ON.\r\n")
	} else {
		return send_argument_syntax_error(s)
	}
}

// Client sent RNFR command, returns false if connection ended.
func command_rename_from(s TcpStream, receive_buffer []byte, name_file_or_dir_for_rename string) bool {
	var tmp_vec []byte

	remove_command(receive_buffer, tmp_vec, 5)

	replace_backslash(tmp_vec)

	*name_file_or_dir_for_rename = string(tmp_vec)

	return send_message(s, "350 Requested file action pending further information.\r\n")
}

// Client sent RNTO command, returns false if connection ended.
func command_rename_to(s TcpStream, receive_buffer []byte, name_file_or_dir_for_rename string) bool {
	var tmp_vec []byte

	remove_command(receive_buffer, tmp_vec, 5)

	replace_backslash(tmp_vec)

	var name_file_or_dir_to_rename = string(tmp_vec)

	if (0 == name_file_or_dir_for_rename.len()) || (0 == name_file_or_dir_to_rename.len()) {
		name_file_or_dir_for_rename.clear()

		return send_message(s, "503 Bad sequence of commands.\r\n")
	}

	var v []string = name_file_or_dir_to_rename.split("\\").collect()

	var name = v.pop().unwrap()

	var result = execute_system_command(SYSTEM_COMMAND_RENAME, &name_file_or_dir_for_rename, name)

	name_file_or_dir_for_rename.clear()

	if result != 0 {
		return send_message(s, "503 Bad sequence of commands.\r\n")
	} else {
		return send_message(s, "250 Requested file action okay, file renamed.\r\n")
	}
}

// Client sent MFMT command, returns false if connection ended.
func command_mfmt(s TcpStream, receive_buffer []byte) bool {
	var tmp_vec []byte

	remove_command(receive_buffer, tmp_vec, 4)

	var mdya = string(tmp_vec)

	var v []string = mdya.split_whitespace().collect()

	var date_time_mfmt = v[0]

	//var date_time_for_file = NaiveDateTime::parse_from_str(date_time_mfmt, "%Y%m%d%H%M%S").unwrap();

	var file_name = string(tmp_vec[15:])

	//var mtime = FileTime::from_unix_time(date_time_for_file.and_utc().timestamp(), 0);

	var _ = set_file_mtime(file_name.clone(), mtime)

	var send_buffer = fmt.Sprintf("213 Modify=%s; %s\r\n", date_time_mfmt, file_name)

	return send_message(s, &send_buffer)
}

// Client sent unknown command, returns false if fails.
func command_unknown(s TcpStream) bool {
	return send_message(s, "550 unrecognised command.\r\n")
}

// Takes a string with a 4 letter command at beginning and saves an output string with this removed.
func remove_command(input_string, output_string []byte, skip_characters uint) {
	var i uint
	var length uint = len(input_string)

	for (i + skip_characters + 1) < length {
		output_string.push(input_string[i+skip_characters+1])
		i += 1
	}
}

// Check is inputted string is valid email address (only requires an '@' before a '.').
func is_email_address(address []byte) bool {
	// First character must be a-z or A-Z.
	if !is_alphabetical(address[0]) {
		return false
	}

	var at_index int32 = -1
	var dot_index int32 = -1

	var length uint = address.len()
	var i uint = 1

	for i < length {
		var c = address[i]

		if !is_alphabetical(c) && !is_numerical(c) {
			if c == '@' {
				at_index = i
			} else if c == '.' {
				dot_index = i
			} else {
				return false
			}
		}
		i++
	}

	return at_index != -1 && dot_index != -1 && at_index < dot_index
}

// Returns true if the character is alphabetical.
func is_alphabetical(c uint8) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// Returns true if the character is a number.
func is_numerical(c uint8) bool {
	return c >= '0' && c <= '9'
}

// Sends client the closing connection method and closes the socket.
func close_client_connection(s TcpStream) {
	send_message(s, "221 FTP server closed the connection.\r\n")

	fmt.Println("Disconnected from client.")
}

// Replace '/' to '\' for Windows
func replace_backslash(buffer []byte) {
	var i uint

	for i < buffer.len() {
		if '/' == buffer[i] {
			buffer[i] = '\\'
		}
		i++
	}
}

// Converting cyrillic characters between Android and Windows 7
func simple_conv(in_string, out_string []byte, tuda_suda bool) {
	const ALL_SYMBOLS_FOR_CONVERT uint = 31 + 31 + 4 + 1

	TABLE_FOR_CONVERT_TUDA := [][]byte{
		// small
		{0xd0, 0xb9, 0xE9, 0},
		{0xd1, 0x86, 0xF6, 0},
		{0xd1, 0x83, 0xF3, 0},
		{0xd0, 0xba, 0xEA, 0},
		{0xd0, 0xb5, 0xE5, 0},
		{0xd0, 0xbd, 0xED, 0},
		{0xd0, 0xb3, 0xE3, 0},
		{0xd1, 0x88, 0xF8, 0},
		{0xd1, 0x89, 0xF9, 0},
		{0xd0, 0xb7, 0xE7, 0},
		{0xd1, 0x85, 0xF5, 0},
		{0xd1, 0x84, 0xF4, 0},
		{0xd1, 0x8b, 0xFB, 0},
		{0xd0, 0xb2, 0xE2, 0},
		{0xd0, 0xb0, 0xE0, 0},
		{0xd0, 0xbf, 0xEF, 0},
		{0xd1, 0x80, 0xF0, 0},
		{0xd0, 0xbe, 0xEE, 0},
		{0xd0, 0xbb, 0xEB, 0},
		{0xd0, 0xb4, 0xE4, 0},
		{0xd0, 0xb6, 0xE6, 0},
		{0xd1, 0x8d, 0xFD, 0},
		{0xd1, 0x8f, 0xFF, 0},
		{0xd1, 0x87, 0xF7, 0},
		{0xd1, 0x81, 0xF1, 0},
		{0xd0, 0xbc, 0xEC, 0},
		{0xd0, 0xb8, 0xE8, 0},
		{0xd1, 0x82, 0xF2, 0},
		{0xd1, 0x8c, 0xFC, 0},
		{0xd0, 0xb1, 0xE1, 0},
		{0xd1, 0x8e, 0xFE, 0},
		// big
		{0xd0, 0x99, 0xC9, 0},
		{0xd0, 0xa6, 0xD6, 0},
		{0xd0, 0xa3, 0xD3, 0},
		{0xd0, 0x9a, 0xCA, 0},
		{0xd0, 0x95, 0xC5, 0},
		{0xd0, 0x9d, 0xCD, 0},
		{0xd0, 0x93, 0xC3, 0},
		{0xd0, 0xa8, 0xD8, 0},
		{0xd0, 0xa9, 0xD9, 0},
		{0xd0, 0x97, 0xC7, 0},
		{0xd0, 0xa5, 0xD5, 0},
		{0xd0, 0xa4, 0xD4, 0},
		{0xd0, 0xab, 0xDB, 0},
		{0xd0, 0x92, 0xC2, 0},
		{0xd0, 0x90, 0xC0, 0},
		{0xd0, 0x9f, 0xCF, 0},
		{0xd0, 0xa0, 0xD0, 0},
		{0xd0, 0x9e, 0xCE, 0},
		{0xd0, 0x9b, 0xCB, 0},
		{0xd0, 0x94, 0xC4, 0},
		{0xd0, 0x96, 0xC6, 0},
		{0xd0, 0xad, 0xDD, 0},
		{0xd0, 0xaf, 0xDF, 0},
		{0xd0, 0xa7, 0xD7, 0},
		{0xd0, 0xa1, 0xD1, 0},
		{0xd0, 0x9c, 0xCC, 0},
		{0xd0, 0x98, 0xC8, 0},
		{0xd0, 0xa2, 0xD2, 0},
		{0xd0, 0xac, 0xDC, 0},
		{0xd0, 0x91, 0xC1, 0},
		{0xd0, 0xae, 0xDE, 0},

		{0xd0, 0xaa, 0xda, 0}, // big "b
		{0xd1, 0x8a, 0xfa, 0}, // small "b
		{0xd0, 0x81, 0xa8, 0}, // big :E
		{0xd1, 0x91, 0xb8, 0}, // small :e

		{0xe2, 0x84, 0x96, 0xb9}} // N

	TABLE_FOR_CONVERT_SUDA := [][]byte{
		// small
		{0xd0, 0xb9, 0xA9, 0},
		{0xd1, 0x86, 0xE6, 0},
		{0xd1, 0x83, 0xE3, 0},
		{0xd0, 0xba, 0xAA, 0},
		{0xd0, 0xb5, 0xA5, 0},
		{0xd0, 0xbd, 0xAD, 0},
		{0xd0, 0xb3, 0xA3, 0},
		{0xd1, 0x88, 0xE8, 0},
		{0xd1, 0x89, 0xE9, 0},
		{0xd0, 0xb7, 0xA7, 0},
		{0xd1, 0x85, 0xE5, 0},
		{0xd1, 0x84, 0xE4, 0},
		{0xd1, 0x8b, 0xEB, 0},
		{0xd0, 0xb2, 0xA2, 0},
		{0xd0, 0xb0, 0xA0, 0},
		{0xd0, 0xbf, 0xAF, 0},
		{0xd1, 0x80, 0xE0, 0},
		{0xd0, 0xbe, 0xAE, 0},
		{0xd0, 0xbb, 0xAB, 0},
		{0xd0, 0xb4, 0xA4, 0},
		{0xd0, 0xb6, 0xA6, 0},
		{0xd1, 0x8d, 0xED, 0},
		{0xd1, 0x8f, 0xEF, 0},
		{0xd1, 0x87, 0xE7, 0},
		{0xd1, 0x81, 0xE1, 0},
		{0xd0, 0xbc, 0xAC, 0},
		{0xd0, 0xb8, 0xA8, 0},
		{0xd1, 0x82, 0xE2, 0},
		{0xd1, 0x8c, 0xEC, 0},
		{0xd0, 0xb1, 0xA1, 0},
		{0xd1, 0x8e, 0xEE, 0},
		// big
		{0xd0, 0x99, 0x89, 0},
		{0xd0, 0xa6, 0x96, 0},
		{0xd0, 0xa3, 0x93, 0},
		{0xd0, 0x9a, 0x8A, 0},
		{0xd0, 0x95, 0x85, 0},
		{0xd0, 0x9d, 0x8D, 0},
		{0xd0, 0x93, 0x83, 0},
		{0xd0, 0xa8, 0x98, 0},
		{0xd0, 0xa9, 0x99, 0},
		{0xd0, 0x97, 0x87, 0},
		{0xd0, 0xa5, 0x95, 0},
		{0xd0, 0xa4, 0x94, 0},
		{0xd0, 0xab, 0x9B, 0},
		{0xd0, 0x92, 0x82, 0},
		{0xd0, 0x90, 0x80, 0},
		{0xd0, 0x9f, 0x8F, 0},
		{0xd0, 0xa0, 0x90, 0},
		{0xd0, 0x9e, 0x8E, 0},
		{0xd0, 0x9b, 0x8B, 0},
		{0xd0, 0x94, 0x84, 0},
		{0xd0, 0x96, 0x86, 0},
		{0xd0, 0xad, 0x9D, 0},
		{0xd0, 0xaf, 0x9F, 0},
		{0xd0, 0xa7, 0x97, 0},
		{0xd0, 0xa1, 0x91, 0},
		{0xd0, 0x9c, 0x8C, 0},
		{0xd0, 0x98, 0x88, 0},
		{0xd0, 0xa2, 0x92, 0},
		{0xd0, 0xac, 0x9C, 0},
		{0xd0, 0x91, 0x81, 0},
		{0xd0, 0xae, 0x9E, 0},

		{0xd0, 0xaa, 0xda, 0}, // big "b
		{0xd1, 0x8a, 0xfa, 0}, // small "b
		{0xd0, 0x81, 0xa8, 0}, // big :E
		{0xd1, 0x91, 0xb8, 0}, // small :e

		{0xe2, 0x84, 0x96, 0xfc}} // N

	var in_len = in_string.len()

	if is_debug() {
		//for x in &in_string {
		//    print!("0x{:x}, ", x);
		//}
		fmt.Println("")
	}

	var i uint

	if tuda_suda {
		for i < in_len {
			if '\xd0' == in_string[i] || '\xd1' == in_string[i] {
				var is_found = false
				var q uint

				for q < ALL_SYMBOLS_FOR_CONVERT-1 {
					if TABLE_FOR_CONVERT_TUDA[q][0] == in_string[i] && TABLE_FOR_CONVERT_TUDA[q][1] == in_string[i+1] {
						out_string.push(TABLE_FOR_CONVERT_TUDA[q][2])
						is_found = true
						break
					}

					q += 1
				}

				if is_found {
					i += 1
				}
			} else if '\xe2' == in_string[i] {
				var is_found = false
				var q = ALL_SYMBOLS_FOR_CONVERT - 1

				for q < ALL_SYMBOLS_FOR_CONVERT {
					if TABLE_FOR_CONVERT_TUDA[q][0] == in_string[i] && TABLE_FOR_CONVERT_TUDA[q][1] == in_string[i+1] && TABLE_FOR_CONVERT_TUDA[q][2] == in_string[i+2] {
						out_string.push(TABLE_FOR_CONVERT_TUDA[q][3])
						is_found = true
						break
					}

					q += 1
				}

				if is_found {
					i += 2
				}
			} else {
				out_string.push(in_string[i])
			}

			i += 1
		}
	} else {
		for i < in_len {
			var is_found = false
			var q = 0

			for q < ALL_SYMBOLS_FOR_CONVERT-1 {
				if TABLE_FOR_CONVERT_SUDA[q][2] == in_string[i] {
					out_string.push(TABLE_FOR_CONVERT_SUDA[q][0])
					out_string.push(TABLE_FOR_CONVERT_SUDA[q][1])
					is_found = true
					break
				}
				q += 1
			}

			if !is_found {
				var is_found2 = false
				var q = ALL_SYMBOLS_FOR_CONVERT - 1

				for q < ALL_SYMBOLS_FOR_CONVERT {
					if TABLE_FOR_CONVERT_SUDA[q][3] == in_string[i] {
						out_string.push(TABLE_FOR_CONVERT_SUDA[q][0])
						out_string.push(TABLE_FOR_CONVERT_SUDA[q][1])
						out_string.push(TABLE_FOR_CONVERT_SUDA[q][2])
						is_found2 = true
						break
					}
					q += 1
				}

				if !is_found2 {
					out_string.push(in_string[i])
				}
			}

			i += 1
		}
	}

	if is_debug() {
		//for x in out_string {
		//    print!("0x{:x}, ", x);
		//}
		fmt.Println("")
	}
}
