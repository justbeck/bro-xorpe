@load bintools
@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

module XorDetect;


export {
	redef record Files::AnalyzerArgs += {

		# Adding an optional xor_key to the file extraction. 
		# If this is set we'll xor the file with the key before saving the file
		xor_key: string &optional;
	};

	redef enum Notice::Type += {
		Binary
	};

}


function on_add(f: fa_file, args: Files::AnalyzerArgs)
	{

	if ( ! args?$extract_filename )
		args$extract_filename = cat("extract-", f$source, "-", f$id);
	
	if ( args?$xor_key && |args$xor_key| > 0){

		NOTICE([$note=Binary, $msg="XOR'd Binary Detected", $sub=BinTools::hex(args$xor_key), $f=f]);

	}	


	}

# Emulates Python's range() function
function range(start: int, stop: int, step: int, results: vector of int &default=vector()) : vector of int
	{

		local new_start = start + step;
		results[|results|] = start;

		if(new_start >= stop){
			return results;
		} else {
			return range(new_start, stop, step, results);
		}

	}

# Given an input_string, determine if there's a pattern of test_length characters that's repeating
function does_it_repeat(input_string: string, test_length: int) : bool
	{
		local key = input_string[0:test_length];
		local step_values = range(test_length, |input_string|, test_length);

		for(x in step_values){
			local i = step_values[x];

			local test_string: string = input_string[i:i+test_length-1];

			if(key[0:|test_string| - 1] != test_string)
				{
					return F;
				}
		}

		return T;
	}


event bro_init()
	{	

	# Hook in to File Analyzer on extraction. Used to write XOR'd binary to log file
	Files::register_analyzer_add_callback(Files::ANALYZER_EXTRACT, on_add);

	}



event file_new(f: fa_file)
	{

	# For now, make sure we capture enough of the file in the first block to try the XORing
	if (! f?$bof_buffer){ 
		return;
	}

	if(f$bof_buffer_size < 117){
		return;
	}

	# On most XOR'd binaries (with no offsets) this should contain the XOR'd string of "This program cannot be run in DOS mode."
	local binary_string = f$bof_buffer[78:116];

	# The string we're looking for
	local original_string = "This program cannot be run in DOS mode.";

	# This is binary_string ^ original_string. If this string contains repeatable patterns the binary is likely XOR'd
	local xor_diff:string = "";

	local position_counter:int = 0;
	for(c in binary_string){
		xor_diff += BinTools::xor(c, original_string[position_counter]);

		position_counter += 1;
	}

	# A vector of the different key sizes we're going to try. (1, 2, 3, 4, ... 16)
	local key_sizes = range(1, 17, 1);

	for(i in key_sizes)
	{
		local key_size = key_sizes[i];

		# See if there's a repeating pattern of key_size in the xor_diff
		if(does_it_repeat(xor_diff, key_size)){

			local xor_key = xor_diff[0:key_size - 1];
			
			if(|xor_key| > 0){

				# If this is an un-xored binary, let's ignore it
				if(xor_key == "\0")			
				{
					return;
				}

				# We started looking for the XOR key at offset 78 in the file. If |xor_key| % 78 != 0, we have to shift the XOR key
				# This is a little clunky as I couldn't find a modulus function
				if(|xor_key| > 1){
					local key_offset = 78;
					local steps = range(0, key_offset, |xor_key|);
					local shift = 78 - steps[|steps| - 1];
					xor_key = xor_key[shift:|xor_key|] + xor_key[0:shift - 1];
				}

				# Add the XOR key to the extractor args
				local extract_args: Files::AnalyzerArgs;
				extract_args$xor_key = xor_key;

				Files::add_analyzer(f, Files::ANALYZER_EXTRACT, extract_args);
		
				return;
			}
		}
	}

	}



