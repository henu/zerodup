import math
import shutil


def print_limited(*texts, end='\n', flush=True):

    max_length = shutil.get_terminal_size()[0] - 1

    # If there is a \r character in the beginning, move it to its own text
    if texts and len(texts[0]) > 1 and texts[0][0] == '\r':
        texts = ('\r',) + (texts[0][1:],) + texts[1:]

    # Calculate text lengths
    texts_lens = [0 if text == '\r' else len(text) for text in texts]

    # TODO: Handle situation when there are too many texts to cut it perfectly
    while True:

        # Check how much cutting is needed
        cut_amount = sum(texts_lens) - max_length
        if cut_amount <= 0:
            break

        # Check what texts are the longest ones
        texts_by_length = sorted(enumerate(texts_lens), key=lambda num_and_text_len: -num_and_text_len[1])
        # Count how many should be cutted this time, and what is the maximum cut length
        cuts_count = 1
        while cuts_count < len(texts_by_length) and texts_by_length[0][1] == texts_by_length[cuts_count][1]:
            cuts_count += 1
        max_cut = None
        if cuts_count < len(texts_by_length):
            max_cut = texts_by_length[0][1] - texts_by_length[cuts_count][1]

        # Calculate how much is cut in total this time
        if max_cut is not None:
            assert max_cut > 0
            total_cut = min(cut_amount, max_cut * cuts_count)
        else:
            total_cut = cut_amount
        assert total_cut > 0

        # Do the cutting
        cut_amount_left = cut_amount
        for cut_i in range(cuts_count):
            text_i = texts_by_length[cut_i][0]
            cut_now = min(math.ceil(total_cut / cuts_count), cut_amount_left)
            assert cut_now >= 0
            texts_lens[text_i] -= cut_now
            cut_amount_left -= cut_now

    # Now do the actual cutting
    new_texts = []
    for text, new_len in zip(texts, texts_lens):
        if len(text) <= new_len or text == '\r':
            new_texts.append(text)
        else:
            front_len = (new_len - 5) // 2
            back_len = new_len - 5 - front_len
            new_texts.append(text[:front_len] + ' ... ' + text[-back_len:])
        texts = new_texts

    text = ''.join(texts)
    print(text, end=end, flush=flush)
