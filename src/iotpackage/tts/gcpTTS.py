from google.cloud import texttospeech

voice = texttospeech.VoiceSelectionParams(
    language_code="en-US", ssml_gender=texttospeech.SsmlVoiceGender.NEUTRAL
)

audio_config = texttospeech.AudioConfig(
    audio_encoding=texttospeech.AudioEncoding.MP3
)

def convertTextToSpeechForVA(wake_word, text, output_fp):
    client = texttospeech.TextToSpeechClient()
    synthesis_input = texttospeech.SynthesisInput(ssml=f'{wake_word},<break time="300ms"/> {text}')
    
    response = client.synthesize_speech(
        input=synthesis_input, voice=voice, audio_config=audio_config
    )

    with open(output_fp, "wb") as out:
        out.write(response.audio_content)
    print(f'Audio content written to file "{output_fp}"')
    return output_fp
