# require 'spec_helper'

describe 'trailing_newline' do
  let(:msg) { 'expected newline at the end of the file' }

  context 'with fix disabled' do
    context 'code not ending with a newline' do
      let(:code) { "'test'" }

      it 'should detect a single problem' do
        expect(problems).to have(1).problem
      end

      it 'should create a warning' do
        expect(problems).to contain_warning(msg).on_line(1).in_column(6)
      end
    end

    context 'code ending with a newline' do
      let(:code) { "'test'\n" }

      it 'should not detect any problems' do
        expect(problems).to have(0).problems
      end
    end
  end
end