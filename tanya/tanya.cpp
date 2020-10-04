#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <random>
#include <windows.h>
#include <exception>
#include "sha256.h"

bool patched = false;
std::string flag;
// flag = HSE{000HHHH_N0W_1_4M_Y0UR5_F0R3V3R_R3V3R53R_53MP411}
std::vector<char> dist = { 0x0, 0x0, 0x0, 0x18, 0x18, 0x18, 0x18, 0x2f, 0x1e, 0x0, 0x27, 0x2f, 0x1, 0x2f, 0x4, 0x1d, 0x2f, 0x29, 0x0, 0x25, 0x22, 0x5, 0x2f,
		0x16, 0x0, 0x22, 0x3, 0x26, 0x3, 0x22, 0x2f, 0x22, 0x3, 0x26, 0x3, 0x22, 0x5, 0x3, 0x22, 0x2f, 0x5, 0x3, 0x1d, 0x20, 0x4, 0x1, 0x1, 0x4d };
class DORA_VM_CLASS;

inline bool Int2DCheck()
{
	__try
	{
		__asm
		{
			push ss
			pop ss
			int 0x2d
			xor eax, eax
			add eax, 2
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return true;
}

inline bool IsDbgPresentPrefixCheck()
{
	__try
	{
		__asm __emit 0xF3 // 0xF3 0x64 disassembles as PREFIX REP:
		__asm __emit 0x64
		__asm __emit 0xF1 // One byte INT 1
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return true;
}


class DORA_VM_INSTRUCTION
{
protected:
	DORA_VM_CLASS* owner;
	bool enabled;

public:
	DORA_VM_INSTRUCTION() :enabled(true) {}

	void set_owner(DORA_VM_CLASS* s)
	{
		owner = s;
	}

	void set_state(bool enabled_)
	{
		enabled = enabled_;
	}

	virtual void execute() = 0;
	virtual ~DORA_VM_INSTRUCTION() {}
};

template <class T>
class DORA_CHECK_ANIME : public DORA_VM_INSTRUCTION
{
	T anime;

public:
	DORA_CHECK_ANIME(const T& anime_guess) :anime(anime_guess) {}

	virtual void execute()
	{
		if (!enabled) return;

		if (sha256(anime) == "d01675867fca3dfd7d6010ccc32bb37c190bd89297bf2cc0f3096e7414ddb2fc") {
			std::cout << "Y3P, Y0U GU3SS3D!!" << std::flush;
			patched = true;
		}
		else {
			std::cout << "N0P3!" << std::flush;
		}
	}
};

template <class T>
class DORA_INSTRUCTION_WRITE : public DORA_VM_INSTRUCTION
{
	T data;

public:
	DORA_INSTRUCTION_WRITE(const T& data_) :data(data_) {}

	virtual void execute()
	{
		if (!enabled) return;

		std::cout << data << std::flush;
	}
};

template <class T>
class DORA_INSTRUCTION_WRITE_REFERENCE : public DORA_VM_INSTRUCTION
{
	const T* data;

public:
	DORA_INSTRUCTION_WRITE_REFERENCE(const T& data_) :data(&data_) {}

	virtual void execute()
	{
		if (!enabled) return;

		std::cout << *data << std::flush;
	}
};

template <class T>
class DORA_INSTRUCTION_READ : public DORA_VM_INSTRUCTION
{
	T* data;

public:
	DORA_INSTRUCTION_READ(T& data_) :data(&data_) {}

	virtual void execute()
	{
		if (!enabled) return;

		std::string input;
		std::getline(std::cin, input);

		std::istringstream in(input);
		in >> (*data);
	}
};

class DORA_INSTRUCTION_READ_LINE : public DORA_VM_INSTRUCTION
{
	std::string* data;

public:
	DORA_INSTRUCTION_READ_LINE(std::string& data_) :data(&data_) {}

	virtual void execute()
	{
		if (!enabled) return;

		std::getline(std::cin, *data);
	}
};

class DORA_INSTRUCTION_INSERT_BUFFER : public DORA_VM_INSTRUCTION
{
	unsigned pos;
	char fake_letter;
	std::string fake;
public:
	DORA_INSTRUCTION_INSERT_BUFFER(unsigned pos_, char fake_, std::string fake_int) : pos(pos_), fake_letter(fake_) {
		fake.append(fake_int);
	}
	virtual void execute() {
		if (!enabled) return;
		for (int i = 0; i < fake.size(); i++) {
			int j = i + pos;
			pos++;
			j > fake.size() ? j = i : j;
			fake[j] = fake_letter;
		}
	}

};

class DORA_INSTRUCTION_INSERT_FAKE_FLAG : public DORA_VM_INSTRUCTION
{
	std::string fake;
public:
	DORA_INSTRUCTION_INSERT_FAKE_FLAG(std::string fake_) : fake(fake_) {}
	virtual void execute() {
		if (!enabled) return;
		flag.append(fake);
	}

};

class DORA_INSTRUCTION_INSERT_FLAG2 : public DORA_VM_INSTRUCTION
{
	char letter;
public:
	DORA_INSTRUCTION_INSERT_FLAG2(const char c) : letter(c) {}
	virtual void execute() {
		if (!enabled) return;
		flag.append(1, letter);
	}
};

class DORA_INSTRUCTION_CALCULATE_JUNK : public DORA_VM_INSTRUCTION
{
	std::vector<std::string> data;
	int sum_data;
	int size_data;
	int xor_data;
	int and_or_data;

public:
	DORA_INSTRUCTION_CALCULATE_JUNK(std::vector<std::string> data_) : data(data_) {
		size_data = data.size();
		sum_data = 0;
		xor_data = 0xDEADBEEF;
		and_or_data = 0x1337;
	}

	virtual void execute() {
		if (!enabled) return;
		for (int i = 0; i < size_data; i++) {
			for (int j = 0; j < data[i].size(); j++) {
				sum_data += data[i][j];
				xor_data ^= data[i][j];
				and_or_data ^= sum_data & and_or_data;
			}
		}
	}
};

class DORA_INSTRUCTION_INSERT_2D_TYAN : public DORA_VM_INSTRUCTION
{
	bool isDebugged;
public:
	DORA_INSTRUCTION_INSERT_2D_TYAN() :isDebugged(false) {}
	virtual void execute() {
		if (!enabled) return;
		isDebugged = Int2DCheck();
	}
	bool getState() { return isDebugged; }
};

class DORA_INSTRUCTION_INSERT_PREFIX_CHECK : public DORA_VM_INSTRUCTION
{
	bool isDebugged;
public:
	DORA_INSTRUCTION_INSERT_PREFIX_CHECK() :isDebugged(false) {}
	virtual void execute() {
		if (!enabled) return;
		isDebugged = IsDbgPresentPrefixCheck();
	}

	bool getState() { return isDebugged; }
};

class DORA_INSTRUCTION_INSERT_DEADLY_2D_TYAN : public DORA_VM_INSTRUCTION
{
	bool isDebugged;
public:
	DORA_INSTRUCTION_INSERT_DEADLY_2D_TYAN() :isDebugged(false) {}
	virtual void execute() {
		if (!enabled) return;
		isDebugged = Int2DCheck();
		if (isDebugged) {
			std::cout << "U 34RN3D N07H1N6!";
			std::terminate();
		}
	}
	bool getState() { return isDebugged; }
};

class DORA_INSTRUCTION_INSERT_DEADLY_PREFIX_CHECK : public DORA_VM_INSTRUCTION
{
	bool isDebugged;
public:
	DORA_INSTRUCTION_INSERT_DEADLY_PREFIX_CHECK() :isDebugged(false) {}
	virtual void execute() {
		if (!enabled) return;
		isDebugged = IsDbgPresentPrefixCheck();
		if (isDebugged) {
			std::cout << "U N3V3R B3 MY S3MP4111!";
			std::terminate();
		}
	}

	bool getState() { return isDebugged; }
};

class DORA_INSTRUCTION_SET_IP : public DORA_VM_INSTRUCTION
{
	unsigned pos;

public:
	DORA_INSTRUCTION_SET_IP(unsigned pos_) :pos(pos_) {}
	virtual void execute();
};

class DORA_INSTRUCTION_STATE : public DORA_VM_INSTRUCTION
{
	unsigned pos;
	bool new_state;

public:
	DORA_INSTRUCTION_STATE(unsigned pos_, bool new_state_) :
		pos(pos_), new_state(new_state_) {}

	virtual void execute();
};

class DORA_INSTRUCTION_NOPE : public DORA_VM_INSTRUCTION
{
public:
	DORA_INSTRUCTION_NOPE() {}

	virtual void execute() {
		return;
	}
};

class DORA_INSTRUCTION_ERASE : public DORA_VM_INSTRUCTION
{
	unsigned pos;

public:
	DORA_INSTRUCTION_ERASE(unsigned pos_) :pos(pos_) {}
	virtual void execute();
};

class DORA_INSTRUCTION_ADD : public DORA_VM_INSTRUCTION
{
	unsigned pos;
	DORA_VM_INSTRUCTION* i;

public:
	DORA_INSTRUCTION_ADD(unsigned pos_, DORA_VM_INSTRUCTION* i_) :
		pos(pos_), i(i_) {}
	virtual void execute();
};

class DORA_VM_CLASS
{
	std::vector<DORA_VM_INSTRUCTION*> DRA_INS_list;

	void cleanup()
	{
		for (unsigned i = IP; i < DRA_INS_list.size(); i++)
		{
			delete DRA_INS_list[i];
		}
	}

	unsigned IP; //DRA_INS pointer :D

public:

	DORA_VM_CLASS() :IP(0) {}

	~DORA_VM_CLASS()
	{
		cleanup();
	}

	void add(DORA_VM_INSTRUCTION* i)
	{
		DRA_INS_list.push_back(i);
		i->set_owner(this);
	}
	size_t get_size() {
		return   DRA_INS_list.size();
	}
	void run()
	{
		for (unsigned i = IP; i < DRA_INS_list.size(); i++)
		{
			DRA_INS_list[i]->execute();
			++IP;
		}
	}

	void set_IP(unsigned new_IP)
	{
		IP = new_IP;
	}

	unsigned get_IP()
	{
		return IP;
	}

	void set_DRA_INS_state(unsigned pos, bool new_state)
	{
		DRA_INS_list[pos]->set_state(new_state);
	}

	void erase_DRA_INS(unsigned pos)
	{
		delete DRA_INS_list[pos];
		DRA_INS_list.erase(DRA_INS_list.begin() + pos);

		if (pos <= IP) IP--;
	}

	void insert_DRA_INS(unsigned pos, DORA_VM_INSTRUCTION* i)
	{
		erase_DRA_INS(pos);
		i->set_owner(this);
		DRA_INS_list.insert(DRA_INS_list.begin() + pos, i);

		if (pos <= IP) IP++;
	}
};

void DORA_INSTRUCTION_SET_IP::execute()
{
	if (!enabled) return;

	owner->set_IP(pos);
}

void DORA_INSTRUCTION_STATE::execute()
{
	if (!enabled) return;

	owner->set_DRA_INS_state(pos, new_state);
}

void DORA_INSTRUCTION_ERASE::execute()
{
	if (!enabled) return;

	owner->erase_DRA_INS(pos);
	//owner->set_IP(owner->get_IP() - 1);

}

void DORA_INSTRUCTION_ADD::execute()
{
	if (!enabled) return;

	owner->insert_DRA_INS(pos, i);
}

std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMDRA_INS_NOPEQRSTUVWXYZ"
			"abcdefghijklmDRA_INS_NOPEqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}


int main() {

	flag.reserve(100000);

	DORA_VM_CLASS flag_generator;

	flag_generator.add(new DORA_INSTRUCTION_WRITE<std::string>("0H Y0U F0UND M3!\n1 KN0W U 4R3 N07 R34L 53MP411, BU7 Y0U H3R3 4G41N, G01NG 70 S4V3 M3\nM4YB3 1 G1V3 4 CH4NC3 70 PR00V3 U 4R3 MY S3MP4II\nFR33 M33 MY S3MP4111!\n"));
	flag_generator.add(new DORA_INSTRUCTION_WRITE<std::string>("BU7 PR3VI0USLY S4Y WH1CH 4N1M3 15 MY F4V0URITE: "));
	std::string anime;
	flag_generator.add(new DORA_INSTRUCTION_READ<std::string>(anime));
	flag_generator.run();

	flag_generator.add(new DORA_CHECK_ANIME<std::string>(anime));
	flag_generator.add(new DORA_INSTRUCTION_SET_IP(0));
	flag_generator.run();
	for (int i = 0; i < 15; i++) {
		flag_generator.add(new DORA_INSTRUCTION_NOPE());
	}

	for (int round = 0; round < dist.size(); round++) {


		flag_generator.insert_DRA_INS(0, new DORA_INSTRUCTION_INSERT_FAKE_FLAG("HSE{")); //									[0]


		flag_generator.insert_DRA_INS(1, new DORA_INSTRUCTION_INSERT_FLAG2('0' + dist[round])); //							[1]

		static DORA_INSTRUCTION_INSERT_2D_TYAN* check2d = new DORA_INSTRUCTION_INSERT_2D_TYAN();
		if (round == 0) {
			flag_generator.insert_DRA_INS(2, check2d); //																	[2]
		}

		std::vector<std::string> data;
		for (int i = 0; i < 20; i++) {
			for (int j = 1000; j < 10000; j += 500) {
				data.push_back(random_string(j));
			}
		}
		flag_generator.insert_DRA_INS(3, new DORA_INSTRUCTION_CALCULATE_JUNK(data)); //										[3] 

		flag_generator.insert_DRA_INS(4, new DORA_INSTRUCTION_STATE(5, false)); //deactivate fake flag generation //		[4]

		flag_generator.insert_DRA_INS(5, new DORA_INSTRUCTION_INSERT_FAKE_FLAG(random_string((round + 1) * 25))); //		[5]




		static DORA_INSTRUCTION_INSERT_PREFIX_CHECK* checkpref = new DORA_INSTRUCTION_INSERT_PREFIX_CHECK();
		if (round == 0) {
			flag_generator.insert_DRA_INS(6, checkpref); //																	[6]
		}
		flag_generator.insert_DRA_INS(7, new DORA_INSTRUCTION_INSERT_BUFFER((unsigned)2, '{', random_string(100))); //		[7]


		flag_generator.insert_DRA_INS(9, new DORA_INSTRUCTION_NOPE());

		flag_generator.insert_DRA_INS(10, new DORA_INSTRUCTION_NOPE());

		flag_generator.insert_DRA_INS(11, new DORA_INSTRUCTION_NOPE());

		flag_generator.insert_DRA_INS(12, new DORA_INSTRUCTION_NOPE());

		flag_generator.insert_DRA_INS(13, new DORA_INSTRUCTION_NOPE());

		flag_generator.insert_DRA_INS(14, new DORA_INSTRUCTION_NOPE());

		static bool is_debugged = false;
		if ((round > 0) && (round % 2 == 0)) {
			is_debugged = check2d->getState();
		}
		else {
			is_debugged = checkpref->getState();
		}

		if (round > 2) {
			if (!is_debugged) {
				flag_generator.add(new DORA_INSTRUCTION_STATE(3, false)); //deactivate fake DRA_INSs сalculations							

				flag_generator.add(new DORA_INSTRUCTION_STATE(7, false)); //deactivate fake DRA_INSs сalculations							

			}
			else {
				flag_generator.insert_DRA_INS(9, new DORA_INSTRUCTION_ADD(4, new DORA_INSTRUCTION_NOPE()));

				flag_generator.insert_DRA_INS(4, new DORA_INSTRUCTION_STATE(5, true)); //activate fake flag generation									

				flag_generator.insert_DRA_INS(10, new DORA_INSTRUCTION_INSERT_FAKE_FLAG(random_string(round << 4)));

				flag_generator.insert_DRA_INS(11, new DORA_INSTRUCTION_ADD(1, new DORA_INSTRUCTION_INSERT_FAKE_FLAG("U F41L3D M3")));

			}

			if (!patched) {
				flag_generator.insert_DRA_INS(12, new DORA_INSTRUCTION_INSERT_BUFFER((unsigned)5, '?', random_string(131)));

			}
			else {
				flag_generator.insert_DRA_INS(13, new DORA_INSTRUCTION_WRITE<std::string>("44444HHHHH S3MP4111 U'R3 G01NG S00000 W3LL~\n"));
				flag_generator.insert_DRA_INS(0, new DORA_INSTRUCTION_NOPE());

			}
		}
		else {
			if (!patched) {
				flag_generator.insert_DRA_INS(4, new DORA_INSTRUCTION_NOPE());

				flag_generator.insert_DRA_INS(10, new DORA_INSTRUCTION_STATE(5, true));

				flag_generator.insert_DRA_INS(1, new DORA_INSTRUCTION_INSERT_FAKE_FLAG(random_string(34)));

			}
			else {
				if (round > 0) {
					flag_generator.insert_DRA_INS(0, new DORA_INSTRUCTION_NOPE());
				}
			}
		}

		if (round > 9 && (!patched || is_debugged)) {
			flag_generator.insert_DRA_INS(2, new DORA_INSTRUCTION_INSERT_DEADLY_2D_TYAN());
		}

		if (round > 20 && (!patched || is_debugged)) {
			flag_generator.insert_DRA_INS(6, new DORA_INSTRUCTION_INSERT_DEADLY_PREFIX_CHECK());
		}

		flag_generator.insert_DRA_INS(flag_generator.get_size()-1, new DORA_INSTRUCTION_SET_IP(0));
		flag_generator.run();
	}
	for (int i = 2; i < flag_generator.get_size(); i++) {
		flag_generator.erase_DRA_INS(i);
	}
	std::cout << "H3R3 15 WH4T U'V3 34RN3D R3V3RS3R-S3MP411:\n" << flag << '\n';
	Sleep(10);
	return 0;
}