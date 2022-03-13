#include <fstream>
#include <iterator>
#include <algorithm>
#include <lyra/lyra.hpp>
#include <spdlog/spdlog.h>
#include <vector>

using namespace std;

int main(int argc, const char** argv)
{
    string input_file;
    string output_file;
    string start_address{};
    string end_address{};
    string mode;

    auto cli = lyra::opt(input_file, "input")
                ["-i"]["--input"]("Which rom to corrupt")
               | lyra::opt(output_file, "output")
                ["-o"]["--output"]("What filename to output to")
               | lyra::opt(start_address, "start")
                ["-s"]["--start"]("Start of address to corrupt in hexadecimal")
               | lyra::opt(end_address, "end")
                ["-e"]["--end"]("End of address to corrupt in hexadecimal")
               | lyra::opt(mode, "mode")
                ["-m"]["--mode"]("Which mode to use to corrupt: 'up' to modify bytes up by 1, 'down' to modify bytes down by 1");

    auto result = cli.parse({argc, argv});
    if(!result) {
        spdlog::error("Error in command line: {}", result.message());
        return 1;
    }

    if(input_file.empty() || output_file.empty() || mode.empty() || start_address.empty() || end_address.empty()) {
        spdlog::error("input, output, mode, start and end are mandatory arguments. e.g. ./snes-rom-corruptor -i rom.sfc -o corrupt_rom.sfc -m up -s 8000 -e 10000");
        spdlog::error("'{}', '{}', '{}', '{}', '{}'", input_file, output_file, mode, start_address, end_address);
        return 1;
    }

    if(mode != "up" && mode != "down") {
        spdlog::error("mode '{}' unsupported. Supported modes: 'up', 'down'", mode);
        return 1;
    }

    uint64_t start{};
    uint64_t end{};
    {
        stringstream stream;
        stream << start_address;
        stream >> std::hex >> start;
    }

    {
        stringstream stream;
        stream << end_address;
        stream >> std::hex >> end;
    }

    spdlog::info("Corrupting from {:x} to {:x} in mode {}", start, end, mode);

    if(end <= start) {
        spdlog::error("End address has to be higher than start address");
        return 1;
    }

    if(end < 0 || start < 0) {
        spdlog::error("both end and start have to be positive");
        return 1;
    }

    ifstream input(input_file, ios::binary);
    ofstream output(output_file, ios::binary | ios::trunc);

    vector<char> bytes{istreambuf_iterator<char>(input), istreambuf_iterator<char>()};

    if(bytes.size() < end) {
        spdlog::error("rom size 0x{:x} less than 0x{:x}, corrupt rom maybe?", bytes.size(), end);
        return 1;
    }

    if (mode == "up") {
        for(uint64_t i = start; i < end; i++) {
            bytes[i]++;
        }
    } else if (mode == "down") {
        for(uint64_t i = start; i < end; i++) {
            bytes[i]--;
        }
    }

    copy(bytes.begin(), bytes.end(), ostreambuf_iterator<char>(output));

    return 0;
}