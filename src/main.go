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
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var MONTHS = [...]string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

const SYSTEM_COMMAND_DEL = "del"
const SYSTEM_COMMAND_MKDIR = "mkdir"
const SYSTEM_COMMAND_RMDIR = "rmdir"
const SYSTEM_COMMAND_RENAME = "rename"

var SHOW_DEBUG_MESSAGE bool
var CONVERT_CYRILLIC bool

const DEFAULT_PORT = 21
const BIG_BUFFER_SIZE uint = 65535

type TcpStream = net.Conn

// Arguments:
//
//	0:  Program name
//	1:  Port number
//	2:  Debug mode (true/false)
//	3:  Use convert cyrillic file and directory name between Android and Windows 7 (true/false)
func main() {
	set_debug(debug_mode())

	set_convert_cyrillic(convert_cyrillic())

	var env_temp = get_temp_directory()

	if len(env_temp) == 0 {
		log.Fatalln("Error, not find environment <TEMP>!!")
	} else if len(env_temp) > 50 {
		log.Fatalln("Error, very long size for environment <TEMP>!!")
	}

	var port = get_server_address_info()

	listener, err := net.Listen("tcp4", port)
	if err != nil {
		log.Fatalln(err)
	}
	defer listener.Close()

	show_server_info()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalln(err)
			conn.Close()
		}
		go handle_clients(conn)
	}
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
	log.Println("===============================")
	log.Println("     159.334 FTP Server        ")
	log.Println("===============================")
}

// Gets the servers address information based on arguments.
func get_server_address_info() string {
	var result string
	if len(os.Args) > 1 {
		result = fmt.Sprintf(":%s", os.Args[1])
	} else {
		result = fmt.Sprintf(":%d", DEFAULT_PORT)
	}
	return result
}

// Accepts new clients and deals with commands.
func handle_clients(s TcpStream) {
	show_client_info(s)

	if !send_message(s, "220 FTP Server ready.\r\n") {
		close_client_connection(s)
		return
	}

	var success = true
	var authroised_login bool
	var connect_to string
	var client_id int = get_client_port(s)
	var current_directory string
	var name_file_or_dir_for_rename string

	for success {
		success = communicate_with_client(
			s,
			&connect_to,
			&authroised_login,
			client_id,
			&current_directory,
			&name_file_or_dir_for_rename)
	}

	close_client_connection(s)
}

func get_client_port(s TcpStream) int {
	tmp := strings.Split(s.RemoteAddr().String(), ":")[1]
	value, err := strconv.Atoi(tmp)
	if err != nil {
		log.Println(err)
		return 0
	}
	return value
}

// Takes incoming connection and assigns new socket.
func show_client_info(s TcpStream) {
	log.Println("A client has been accepted.")

	addr := strings.Split(s.RemoteAddr().String(), ":")

	log.Printf("Connected to client with IP address: %s, at Port: %s\n", addr[0], addr[1])
}

// Receive and handle messages from client, returns false if client ends connection.
func communicate_with_client(s TcpStream, connect_to *string, authroised_login *bool, client_id int, current_directory *string, name_file_or_dir_for_rename *string) bool {
	var receive_buffer []byte
	var user_name string
	var password string

	if receipt_successful := receive_message(s, &receive_buffer); !receipt_successful {
		return receipt_successful
	}

	var success bool

	if len(receive_buffer) < 4 {
		return command_unknown(s)
	}

	maybe_command := string(receive_buffer[:4])

	switch maybe_command {
	case "USER":
		{
			i_attempts := 0

			for !success && i_attempts < 4 {
				if success = command_user_name(s, receive_buffer, user_name, authroised_login); !success {
					i_attempts++

					if receipt_successful := receive_message(s, &receive_buffer); !receipt_successful {
						return receipt_successful
					}
				}
			}
			return success
		}

	case "PASS":
		success = command_password(s, receive_buffer, password, authroised_login)
	case "SYST":
		success = command_system_information(s)
	case "QUIT":
		success = command_quit()
	case "PORT":
		success = command_port(s, connect_to, receive_buffer)
	case "LIST", "NLST":
		success = command_list(s, connect_to, client_id, *current_directory)
	case "RETR":
		success = command_retrieve(s, connect_to, receive_buffer, *current_directory)
	case "STOR":
		success = command_store(s, connect_to, receive_buffer, *current_directory)
	case "CWD ":
		success = command_change_working_directory(s, receive_buffer, current_directory)
	case "DELE":
		success = command_delete(s, receive_buffer)
	case "MKD ":
		success = command_make_directory(s, receive_buffer)
	case "RMD ":
		success = command_delete_directory(s, receive_buffer)
	case "TYPE":
		success = command_type(s, receive_buffer)
	case "FEAT":
		success = command_feat(s)
	case "OPTS":
		success = command_opts(s, receive_buffer)
	case "RNFR":
		success = command_rename_from(s, receive_buffer, name_file_or_dir_for_rename)
	case "RNTO":
		success = command_rename_to(s, receive_buffer, name_file_or_dir_for_rename)
	case "MFMT":
		success = command_mfmt(s, receive_buffer)
	default:
		success = command_unknown(s)
	}

	return success
}

// Receives message and saves it in receive buffer, returns false if connection ended.
func receive_message(s TcpStream, receive_buffer *[]byte) bool {
	var recv_bytes int
	buffer_for_read := make([]byte, 1)
	var err error

	*receive_buffer = make([]byte, 0)

	for {
		if recv_bytes, err = s.Read(buffer_for_read); err == io.EOF {
			return false
		}

		if recv_bytes == 0 || err != nil {
			log.Println("Read error:", err)
			return false
		}

		if buffer_for_read[0] == '\n' {
			break
		} else if buffer_for_read[0] == '\r' {
			continue
		}

		*receive_buffer = append(*receive_buffer, buffer_for_read[:1]...)
	}

	if is_debug() {
		log.Printf("<--- %s\n", string(*receive_buffer))
	}

	return true
}

// Client sent USER command, returns false if fails.
func command_user_name(s TcpStream, receive_buffer []byte, user_name string, authroised_login *bool) bool {
	remove_command(receive_buffer, &user_name, 4)

	log.Printf("User: \"%s\" attempting to login.\n", user_name)

	*authroised_login = is_valid_user_name(user_name)

	if *authroised_login {
		log.Println("User name valid. Password required.")

		return send_message(s, "331 Authorised login requested, please specify the password.\r\n")
	}

	log.Println("User name unauthorised. Public access only.")

	return send_message(s, "331 Public login requested, please specify email as password.\r\n")
}

// Send message to client, returns true if message was sended.
func send_message(s TcpStream, send_buffer string) bool {
	bytes_for_send := len(send_buffer)
	send_bytes, err := s.Write([]byte(send_buffer))
	if err != nil {
		log.Println(err)
		return false
	}
	if is_debug() {
		log.Printf("---> %s", send_buffer)
	}
	return bytes_for_send == send_bytes
}

// Returns true if valid user name.
func is_valid_user_name(user_name string) bool {
	return user_name == "nhreyes"
}

// Client sent PASS command, returns false if fails.
func command_password(s TcpStream, receive_buffer []byte, password string, authroised_login *bool) bool {
	remove_command(receive_buffer, &password, 4)

	valid_password := is_valid_password(password, authroised_login)

	var send_buffer string

	if valid_password {
		log.Println("Password valid. User logged in.")

		send_buffer = "230 Login successful.\r\n"
	} else {
		log.Println("Password invalid. Login failed.")

		send_buffer = "530 Login authentication failed.\r\n"
	}

	if !send_message(s, send_buffer) {
		return false
	}

	return valid_password
}

// Returns true if valid password.
func is_valid_password(password string, authroised_login *bool) bool {
	if *authroised_login {
		return password == "334"
	}

	return is_email_address(password)
}

// Client sent SYST command, returns false if fails.
func command_system_information(s TcpStream) bool {
	log.Println("System information requested.")

	return send_message(s, "215 Windows Type: WIN64\r\n")
}

// Client sent QUIT command, returns false if fails.
func command_quit() bool {
	log.Println("Client has quit the session.")

	return false
}

// Client sent PORT command, returns false if fails.
func command_port(s TcpStream, connect_to *string, receive_buffer []byte) bool {
	log.Println("===================================================")
	log.Println("\tActive FTP mode, the client is listening...")

	*connect_to = get_client_ip_and_port(receive_buffer)

	if len(*connect_to) == 0 {
		return send_argument_syntax_error(s)
	}

	return send_message(s, "200 PORT Command successful.\r\n")
}

// Gets the client's IP and port number for active connection.
func get_client_ip_and_port(receive_buffer []byte) string {
	var parts []string = strings.Split(string(receive_buffer[5:]), ",")

	if cap(parts) != 6 {
		return ""
	}

	active_ip := parts[:4]
	active_port := make([]int, 2)

	var err error

	if active_port[0], err = strconv.Atoi(parts[4]); err != nil {
		log.Println(err)
		return ""
	}

	if active_port[1], err = strconv.Atoi(parts[5]); err != nil {
		log.Println(err)
		return ""
	}

	ip_buffer := fmt.Sprintf("%s.%s.%s.%s", active_ip[0], active_ip[1], active_ip[2], active_ip[3])
	log.Printf("\tClient's IP is %s\n", ip_buffer)

	port_decimal := active_port[0]<<8 | active_port[1]
	port_buffer := strconv.Itoa(port_decimal)
	log.Printf("\tClient's Port is %s\n", port_buffer)

	return ip_buffer + ":" + port_buffer
}

func send_argument_syntax_error(s TcpStream) bool {
	return send_message(s, "501 Syntax error in arguments.\r\n")
}

// Sends the client a message to say data connection failed.
func send_failed_active_connection(s TcpStream) bool {
	return send_message(s, "425 Something is wrong, can't start active connection.\r\n")
}

// Client sent LIST command, returns false if fails.
func command_list(s TcpStream, connect_to *string, client_id int, current_directory string) bool {
	var tmp = fmt.Sprintf("%s\\%d_tmp_dir.txt", get_temp_directory(), client_id)

	if send_file(s, connect_to, tmp, client_id, current_directory) != 1 {
		return send_message(s, "426 Connection closed; transfer aborted.\r\n")
	}

	return send_message(s, "226 Directory send OK.\r\n")
}

func get_temp_directory() string {
	return os.Getenv("TEMP")
}

func delete_temp_files(file1, file2, file3 string) {
	execute_system_command(SYSTEM_COMMAND_DEL, file1)
	execute_system_command(SYSTEM_COMMAND_DEL, file2)
	execute_system_command(SYSTEM_COMMAND_DEL, file3)
}

// Sends specified file to client, return '1' if not have error.
func send_file(s TcpStream, connect_to *string, file_name string, client_id int, current_directory string) int {
	var tmp string
	var tmp_directory string
	var tmp_file string
	var tmp_dir_directory = "dir /A:D /B"
	var tmp_dir_files = "dir /A:-D /-C"

	if client_id > 0 {
		log.Println("Client has requested the directory listing.")

		year := time.Now().Year()

		path_temp := get_temp_directory()

		tmp = fmt.Sprintf("%s\\%d_tmp_dir.txt", path_temp, client_id)
		tmp_directory = fmt.Sprintf("%s\\%d_tmp_dir2.txt", path_temp, client_id)
		tmp_file = fmt.Sprintf("%s\\%d_tmp_dir3.txt", path_temp, client_id)

		tmp_dir_directory += " >"
		tmp_dir_directory += tmp_directory

		tmp_dir_files += " >"
		tmp_dir_files += tmp_file

		execute_system_command(tmp_dir_files, current_directory)

		execute_system_command(tmp_dir_directory, current_directory)

		f_dir, err := os.Create(tmp)
		if err != nil {
			log.Panicln(err)
			return 0
		}
		defer f_dir.Close()

		f_directory, err := os.Open(tmp_directory)
		if err != nil {
			log.Panicln(err)
			return 0
		}
		defer f_directory.Close()

		var is_first = true

		var buffer []byte
		var buffer_for_read = make([]byte, 1)
		var n int

		for {
			if n, err = f_directory.Read(buffer_for_read); err == io.EOF {
				break
			}
			if n != 1 || err != nil {
				log.Println(err)
				break
			}
			var b byte = buffer_for_read[0]
			if b == '\r' {
				continue
			} else if b == '\n' {
				var tmp_buffer_dir = "drw-rw-rw-    1 user       group        512 Oct 15  2024 "
				if !is_convert_cyrillic() {
					var line = string(buffer)
					tmp_buffer_dir += line
				} else {
					var tmp_new_file_name []byte
					simple_conv(buffer, &tmp_new_file_name, false)
					var str_tmp_new_file_name = string(tmp_new_file_name)
					tmp_buffer_dir += str_tmp_new_file_name
				}
				if !is_first {
					f_dir.Write([]byte("\n"))
				} else {
					is_first = false
				}
				f_dir.Write([]byte(tmp_buffer_dir))
				if is_debug() {
					log.Println(tmp_buffer_dir)
				}
				buffer = buffer[:0]
			} else {
				buffer = append(buffer, b)
			}
		}

		buffer = buffer[:0]

		f_files, err := os.Open(tmp_file)
		if err != nil {
			log.Panicln(err)
			return 0
		}
		defer f_files.Close()

		var skip_lines = 5
		var tmp_file_name string
		var tmp_buffer_file string

		for {
			if n, err = f_files.Read(buffer_for_read); err == io.EOF {
				break
			}
			if n != 1 || err != nil {
				log.Println(err)
				break
			}
			b := buffer_for_read[0]
			if b == '\r' {
				continue
			} else if b == '\n' {
				if skip_lines > 0 {
					skip_lines -= 1
					buffer = buffer[:0]
					continue
				}

				if is_numerical(buffer[0]) {
					line := string(buffer[0:36])

					line_for_split := line
					for strings.Contains(line_for_split, "  ") {
						line_for_split = strings.ReplaceAll(line_for_split, "  ", " ")
					}

					v := strings.Split(line_for_split, " ")

					tmp_date := []byte(v[0])

					i_day, _ := strconv.Atoi(string(tmp_date[0:2]))
					i_month, _ := strconv.Atoi(string(tmp_date[3:5]))
					i_year, _ := strconv.Atoi(string(tmp_date[6:10]))

					var tmp_time = []byte(v[1])

					i_hour, _ := strconv.Atoi(string(tmp_time[0:2]))
					i_minute, _ := strconv.Atoi(string(tmp_time[3:5]))

					var tmp_file_size = v[2]

					file_size, _ := strconv.Atoi(tmp_file_size)

					tmp_file_name_vec := buffer[36:]

					if year == i_year {
						tmp_buffer_file = fmt.Sprintf("-rw-rw-rw-    1 user       group %10d %s %02d %02d:%02d ", file_size, MONTHS[i_month-1], i_day, i_hour, i_minute)
					} else {
						tmp_buffer_file = fmt.Sprintf("-rw-rw-rw-    1 user       group %10d %s %02d  %04d ", file_size, MONTHS[i_month-1], i_day, i_year)
					}
					if !is_convert_cyrillic() {
						tmp_file_name = string(buffer[36:])
						tmp_buffer_file += tmp_file_name
					} else {
						var tmp_new_file_name_vec []byte
						simple_conv(tmp_file_name_vec, &tmp_new_file_name_vec, false)
						var tmp_new_file_name = string(tmp_new_file_name_vec)
						tmp_buffer_file += tmp_new_file_name
					}
					if !is_first {
						f_dir.Write([]byte("\n"))
					} else {
						is_first = false
					}
					f_dir.Write([]byte(tmp_buffer_file))
					if is_debug() {
						log.Println(tmp_buffer_file)
					}
				}
				buffer = buffer[:0]
			} else {
				buffer = append(buffer, b)
			}
		}

		f_dir.Write([]byte("\n"))
	} else {
		log.Printf("Client has requested to retrieve the file: \"%s\".\n", file_name)
	}

	var file_name_for_open string

	if client_id > 0 {
		file_name_for_open = tmp
	} else {
		file_name_for_open = current_directory

		if len(file_name_for_open) > 0 {
			file_name_for_open += "\\"
		}

		file_name_for_open += file_name
	}

	f_in, err := os.OpenFile(file_name_for_open, os.O_RDONLY, 0666)
	if err != nil {
		log.Println("Error:", err)
		if !send_message(s, "550 File name invalid.\r\n") {
			return 0
		}
		return -1
	}
	defer f_in.Close()

	if !send_message(s, "150 Data connection ready.\r\n") {
		if client_id > 0 {
			if !is_debug() {
				delete_temp_files(tmp, tmp_directory, tmp_file)
			}
		}
		return 0
	}

	send_to, err := net.Dial("tcp4", *connect_to)
	if err != nil {
		log.Println(err)
		if client_id > 0 {
			if !is_debug() {
				delete_temp_files(tmp, tmp_directory, tmp_file)
			}
		}
		return 0
	}
	defer send_to.Close()

	temp_buffer := make([]byte, BIG_BUFFER_SIZE)
	var read_bytes int

	for {
		if read_bytes, err = f_in.Read(temp_buffer); err == io.EOF {
			break
		}

		if read_bytes == 0 || err != nil {
			log.Println(err)
			return 0
		}

		var send_bytes int
		if send_bytes, err = send_to.Write(temp_buffer[:read_bytes]); err != nil {
			log.Println(err)
			return 0
		}

		if send_bytes != read_bytes {
			if client_id > 0 {
				if !is_debug() {
					delete_temp_files(tmp, tmp_directory, tmp_file)
				}
			}
			return 0
		}
	}

	if client_id > 0 {
		if !is_debug() {
			delete_temp_files(tmp, tmp_directory, tmp_file)
		}
	}

	log.Println("File sent successfully.")

	return 1
}

// return '0' if not have error.
func execute_system_command(args ...string) int {
	if is_debug() {
		log.Printf("Execute command: %s\n", args)
	}

	cmd_args := []string{"/C"}

	for _, arg := range args {
		cmd_args = append(cmd_args, arg)
	}

	cmd := exec.Command("cmd", cmd_args...)

	if err := cmd.Run(); err != nil {
		log.Println("Error:", err)
		return cmd.ProcessState.ExitCode()
	}

	return 0
}

// Client sent RETR command, returns false if fails.
func command_retrieve(s TcpStream, connect_to *string, receive_buffer []byte, current_directory string) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 4)

	if send_file(s, connect_to, tmp, 0, current_directory) != 1 {
		return send_message(s, "426 Connection closed; transfer aborted.\r\n")
	}

	return send_message(s, "226 File transfer complete.\r\n")
}

// Client sent STORE command, returns false if fails.
func command_store(s TcpStream, connect_to *string, receive_buffer []byte, current_directory string) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 4)

	if !save_file(s, connect_to, tmp, current_directory) {
		return send_message(s, "426 Connection closed; transfer aborted.\r\n")
	}

	return send_message(s, "226 File transfer complete.\r\n")
}

// Sends specified file to client.
func save_file(s TcpStream, connect_to *string, file_name, current_directory string) bool {
	log.Printf("Client has requested to store the file: \"%s\".\n", file_name)

	recv_from, err := net.Dial("tcp4", *connect_to)
	if err != nil {
		log.Println(err)
		send_failed_active_connection(s)
		return false
	}
	defer recv_from.Close()

	if !send_message(s, "150 Data connection ready.\r\n") {
		return false
	}

	file_name_full := current_directory

	if len(file_name_full) > 0 {
		file_name_full += "\\"
	}

	file_name_full += file_name

	f_out_file, err := os.Create(file_name_full)
	if err != nil {
		log.Println(err)
		return false
	}
	defer f_out_file.Close()

	temp_buffer := make([]byte, BIG_BUFFER_SIZE)
	var recv_bytes int

	for {
		if recv_bytes, err = recv_from.Read(temp_buffer); err == io.EOF {
			break
		}

		if err != nil {
			log.Println(err)
			return false
		}

		if recv_bytes > 0 {
			if n, err := f_out_file.Write(temp_buffer[:recv_bytes]); n == 0 || err != nil {
				log.Println(err)
				return false
			}
		}
	}

	log.Println("File saved successfully.")

	return true
}

// Client sent CWD command, returns false if connection ended.
func command_change_working_directory(s TcpStream, receive_buffer []byte, current_directory *string) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 4)

	replace_backslash(&tmp)

	*current_directory = tmp

	if *current_directory == "\\" {
		*current_directory = ""
	}

	return send_message(s, "250 Directory successfully changed.\r\n")
}

// Client sent DELETE command, returns false if connection ended.
func command_delete(s TcpStream, receive_buffer []byte) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 5)

	replace_backslash(&tmp)

	execute_system_command(SYSTEM_COMMAND_DEL, tmp)

	return send_message(s, "250 Requested file action okay, completed.\r\n")
}

// Client sent MKD command, returns false if connection ended.
func command_make_directory(s TcpStream, receive_buffer []byte) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 4)

	replace_backslash(&tmp)

	execute_system_command(SYSTEM_COMMAND_MKDIR, tmp)

	return send_message(s, fmt.Sprintf("257 '/%s' directory created\r\n", tmp))
}

// Client sent RMD command, returns false if connection ended.
func command_delete_directory(s TcpStream, receive_buffer []byte) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 4)

	replace_backslash(&tmp)

	execute_system_command(SYSTEM_COMMAND_RMDIR, tmp)

	return send_message(s, "250 Requested file action okay, completed.\r\n")
}

// Client sent TYPE command, returns false if connection ended.
func command_type(s TcpStream, receive_buffer []byte) bool {
	var type_name string

	remove_command(receive_buffer, &type_name, 4)

	return send_message(s, fmt.Sprintf("200 Type set to %s.\r\n", type_name))
}

// Client sent FEAT command, returns false if fails.
func command_feat(s TcpStream) bool {
	return send_message(s, "211-Extensions supported\r\n UTF8\r\n MFMT\r\n211 end\r\n")
}

// Client sent OPTS command, returns false if connection ended.
func command_opts(s TcpStream, receive_buffer []byte) bool {
	var opts_name string

	remove_command(receive_buffer, &opts_name, 4)

	if opts_name == "UTF8 ON" {
		return send_message(s, "200 UTF8 ON.\r\n")
	}

	return send_argument_syntax_error(s)
}

// Client sent RNFR command, returns false if connection ended.
func command_rename_from(s TcpStream, receive_buffer []byte, name_file_or_dir_for_rename *string) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 5)

	replace_backslash(&tmp)

	*name_file_or_dir_for_rename = tmp

	return send_message(s, "350 Requested file action pending further information.\r\n")
}

// Client sent RNTO command, returns false if connection ended.
func command_rename_to(s TcpStream, receive_buffer []byte, name_file_or_dir_for_rename *string) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 5)

	replace_backslash(&tmp)

	name_file_or_dir_to_rename := tmp

	if 0 == len(*name_file_or_dir_for_rename) || 0 == len(name_file_or_dir_to_rename) {
		*name_file_or_dir_for_rename = ""

		return send_message(s, "503 Bad sequence of commands.\r\n")
	}

	v := strings.Split(name_file_or_dir_to_rename, "\\")

	result := execute_system_command(SYSTEM_COMMAND_RENAME, *name_file_or_dir_for_rename, v[cap(v)])

	*name_file_or_dir_for_rename = ""

	if result != 0 {
		return send_message(s, "503 Bad sequence of commands.\r\n")
	}

	return send_message(s, "250 Requested file action okay, file renamed.\r\n")
}

// Client sent MFMT command, returns false if connection ended.
func command_mfmt(s TcpStream, receive_buffer []byte) bool {
	var mdya string

	remove_command(receive_buffer, &mdya, 4)

	v := strings.Split(mdya, " ")

	date_time_mfmt := v[0]

	year, _ := strconv.Atoi(string(date_time_mfmt[0:4]))
	month, _ := strconv.Atoi(string(date_time_mfmt[4:6]))
	day, _ := strconv.Atoi(string(date_time_mfmt[6:8]))
	hour, _ := strconv.Atoi(string(date_time_mfmt[8:10]))
	minute, _ := strconv.Atoi(string(date_time_mfmt[10:12]))
	seconds, _ := strconv.Atoi(string(date_time_mfmt[12:14]))
	mtime := time.Date(year, time.Month(month), day, hour, minute, seconds, 0, time.UTC)

	var file_name = string(receive_buffer[21:])

	if err := os.Chtimes(file_name, mtime, mtime); err != nil {
		log.Println(file_name, err)

		return send_argument_syntax_error(s)
	}

	return send_message(s, fmt.Sprintf("213 Modify=%s; %s\r\n", date_time_mfmt, file_name))
}

// Client sent unknown command, returns false if fails.
func command_unknown(s TcpStream) bool {
	return send_message(s, "550 unrecognised command.\r\n")
}

// Takes a string with a 4 letter command at beginning and saves an output string with this removed.
func remove_command(input_string []byte, output_string *string, skip_characters uint) {
	*output_string = string(input_string[(skip_characters + 1):])
}

// Check is inputted string is valid email address (only requires an '@' before a '.').
func is_email_address(address string) bool {
	// First character must be a-z or A-Z.
	if !is_alphabetical(address[0]) {
		return false
	}

	var at_index int = -1
	var dot_index int = -1

	var length int = len(address)
	var i int = 1

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

	s.Close()

	log.Println("Disconnected from client.")
}

// Replace '/' to '\' for Windows
func replace_backslash(buffer *string) {
	*buffer = strings.ReplaceAll(*buffer, "/", "\\")
}

// Converting cyrillic characters between Android and Windows 7
func simple_conv(in_string []byte, out_string *[]byte, tuda_suda bool) {
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

	var in_len = len(in_string)
	var i int
	var b byte

	if tuda_suda {
		for i < in_len {
			if '\xd0' == in_string[i] || '\xd1' == in_string[i] {
				var is_found = false
				var q uint

				for q < ALL_SYMBOLS_FOR_CONVERT-1 {
					if TABLE_FOR_CONVERT_TUDA[q][0] == in_string[i] && TABLE_FOR_CONVERT_TUDA[q][1] == in_string[i+1] {
						b = TABLE_FOR_CONVERT_TUDA[q][2]
						*out_string = append(*out_string, b)
						is_found = true
						break
					}

					q++
				}

				if is_found {
					i++
				}
			} else if '\xe2' == in_string[i] {
				var is_found = false
				var q = ALL_SYMBOLS_FOR_CONVERT - 1

				for q < ALL_SYMBOLS_FOR_CONVERT {
					if TABLE_FOR_CONVERT_TUDA[q][0] == in_string[i] && TABLE_FOR_CONVERT_TUDA[q][1] == in_string[i+1] && TABLE_FOR_CONVERT_TUDA[q][2] == in_string[i+2] {
						b = TABLE_FOR_CONVERT_TUDA[q][3]
						*out_string = append(*out_string, b)
						is_found = true
						break
					}

					q++
				}

				if is_found {
					i += 2
				}
			} else {
				*out_string = append(*out_string, byte(in_string[i]))
			}

			i++
		}
	} else {
		for i < in_len {
			var is_found = false
			var q uint

			for q < ALL_SYMBOLS_FOR_CONVERT-1 {
				if TABLE_FOR_CONVERT_SUDA[q][2] == in_string[i] {
					b = TABLE_FOR_CONVERT_SUDA[q][0]
					*out_string = append(*out_string, b)
					b = TABLE_FOR_CONVERT_SUDA[q][1]
					*out_string = append(*out_string, b)
					is_found = true
					break
				}
				q++
			}

			if !is_found {
				var is_found2 = false
				var q = ALL_SYMBOLS_FOR_CONVERT - 1

				for q < ALL_SYMBOLS_FOR_CONVERT {
					if TABLE_FOR_CONVERT_SUDA[q][3] == in_string[i] {
						b = TABLE_FOR_CONVERT_SUDA[q][0]
						*out_string = append(*out_string, b)
						b = TABLE_FOR_CONVERT_SUDA[q][1]
						*out_string = append(*out_string, b)
						b = TABLE_FOR_CONVERT_SUDA[q][2]
						*out_string = append(*out_string, b)
						is_found2 = true
						break
					}
					q++
				}

				if !is_found2 {
					*out_string = append(*out_string, byte(in_string[i]))
				}
			}

			i++
		}
	}

	if is_debug() {
		if len(in_string) != len(*out_string) {
			var tmp []string
			for _, x := range []byte(in_string) {
				tmp = append(tmp, fmt.Sprintf("0x%02x, ", x))
			}
			log.Println(tmp)

			var tmp2 []string
			for _, x := range []byte(*out_string) {
				tmp2 = append(tmp2, fmt.Sprintf("0x%02x, ", x))
			}
			log.Println(tmp2)
		}
	}
}
