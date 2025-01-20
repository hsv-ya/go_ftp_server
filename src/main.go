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
 * The ftp LIST command is fully implemented.
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

const SYSTEM_COMMAND_DEL = "del"
const SYSTEM_COMMAND_MKDIR = "mkdir"
const SYSTEM_COMMAND_RMDIR = "rmdir"
const SYSTEM_COMMAND_RENAME = "rename"

var SHOW_DEBUG_MESSAGE bool

const DEFAULT_PORT = 21
const BIG_BUFFER_SIZE uint = 65535

type TcpStream = net.Conn

// Arguments:
//
//	0:  Program name
//	1:  Port number
//	2:  Debug mode (true/false)
func main() {
	set_debug(debug_mode())

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

		*receive_buffer = append(*receive_buffer, buffer_for_read[0])
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

// Sends specified file to client, return '1' if not have error.
func send_file(s TcpStream, connect_to *string, file_name string, client_id int, current_directory string) int {
	var tmp string

	if client_id > 0 {
		log.Println("Client has requested the directory listing.")

		year := time.Now().Year()

		path_temp := get_temp_directory()

		tmp = fmt.Sprintf("%s\\%d_tmp_dir.txt", path_temp, client_id)

		f_dir, err := os.Create(tmp)
		if err != nil {
			log.Panicln(err)
			return 0
		}
		defer f_dir.Close()

		tmp_dir := current_directory
		if current_directory == "" {
			tmp_dir = "."
		}

		lists, err := os.ReadDir(tmp_dir)
		if err != nil {
			log.Panicln(err)
			return 0
		}

		for _, item := range lists {
			if item.IsDir() {
				f_dir.WriteString("drw-rw-rw-    1 user       group        512 Oct 15  2024 " + item.Name() + "\n")
			} else {
				itemInfo, err := item.Info()
				if err != nil {
					log.Panicln(err)
					continue
				}
				file_size := itemInfo.Size()
				utc := itemInfo.ModTime()
				i_day := utc.Day()
				s_month := utc.Month().String()[0:3]
				i_year := utc.Year()
				i_hour := utc.Hour()
				i_minute := utc.Minute()
				var tmp_buffer_file string
				if year == i_year {
					tmp_buffer_file = fmt.Sprintf("-rw-rw-rw-    1 user       group %10d %s %02d %02d:%02d ", file_size, s_month, i_day, i_hour, i_minute)
				} else {
					tmp_buffer_file = fmt.Sprintf("-rw-rw-rw-    1 user       group %10d %s %02d  %04d ", file_size, s_month, i_day, i_year)
				}
				tmp_buffer_file += item.Name()
				f_dir.WriteString(tmp_buffer_file + "\n")
			}
		}
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
				delete_temp_files(tmp)
			}
		}
		return 0
	}

	send_to, err := net.Dial("tcp4", *connect_to)
	if err != nil {
		log.Println(err)
		if client_id > 0 {
			if !is_debug() {
				delete_temp_files(tmp)
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
					delete_temp_files(tmp)
				}
			}
			return 0
		}
	}

	if client_id > 0 {
		if !is_debug() {
			delete_temp_files(tmp)
		}
	}

	log.Println("File sent successfully.")

	return 1
}

func get_temp_directory() string {
	return os.Getenv("TEMP")
}

func delete_temp_files(file1 string) {
	execute_system_command(SYSTEM_COMMAND_DEL, file1)
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
